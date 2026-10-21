//! Bounded hand-off between tasks: a fixed-capacity channel plus an ordered holdback queue, so a
//! producer that must not block (the 60 Hz loop, the pipeline) never grows memory without limit
//! and never silently loses an item it may not lose.
//!
//! Policy per item is explicit: `push` keeps the item (or reports the holdback full so the
//! caller applies backpressure), `push_or_replace` is for explicitly disposable, superseded
//! updates and coalesces them.
use std::collections::VecDeque;
use tokio::sync::mpsc::{error::TrySendError, Sender};

pub struct Outbox<T> {
    tx: Sender<T>,
    held: VecDeque<T>,
    /// Required items the holdback had no room for (bounded by how many such items exist, e.g.
    /// distinct evidence), kept in order and retried; never discarded.
    spill: VecDeque<T>,
    cap: usize,
    /// Disposable items dropped or coalesced because the consumer was slow.
    pub coalesced: u64,
}

impl<T> Outbox<T> {
    pub fn new(tx: Sender<T>, holdback: usize) -> Self {
        Self {
            tx,
            held: VecDeque::new(),
            spill: VecDeque::new(),
            cap: holdback,
            coalesced: 0,
        }
    }
    /// Move held items into the channel while it has room, in order.
    pub fn flush(&mut self) {
        while self.held.len() < self.cap {
            let Some(item) = self.spill.pop_front() else {
                break;
            };
            self.held.push_back(item);
        }
        while let Some(item) = self.held.pop_front() {
            match self.tx.try_send(item) {
                Ok(()) => {}
                Err(TrySendError::Full(item)) => {
                    self.held.push_front(item);
                    return;
                }
                Err(TrySendError::Closed(_)) => {
                    self.held.clear();
                    return;
                }
            }
        }
    }
    /// Queue an item that must be delivered. `Err(item)` means the holdback is full: the caller
    /// still owns the item and must stop producing (backpressure) or fail loudly.
    pub fn push(&mut self, item: T) -> Result<(), T> {
        self.flush();
        if !self.spill.is_empty() {
            return Err(item);
        }
        if self.held.is_empty() {
            return match self.tx.try_send(item) {
                Ok(()) | Err(TrySendError::Closed(_)) => Ok(()),
                Err(TrySendError::Full(item)) => self.hold(item),
            };
        }
        self.hold(item)
    }
    /// Queue an item that may never be dropped: held if there is room, otherwise spilled.
    pub fn push_required(&mut self, item: T) {
        if let Err(item) = self.push(item) {
            self.spill.push_back(item);
        }
    }
    #[cfg_attr(not(test), allow(dead_code))]
    pub fn spilled(&self) -> usize {
        self.spill.len()
    }
    fn hold(&mut self, item: T) -> Result<(), T> {
        if self.held.len() >= self.cap {
            return Err(item);
        }
        self.held.push_back(item);
        Ok(())
    }
    /// Queue a disposable, superseded-by-the-next update: a queued item for which `same` holds
    /// is replaced instead of growing the queue; when full the update is dropped (and counted).
    pub fn push_or_replace(&mut self, item: T, same: impl Fn(&T, &T) -> bool) {
        self.flush();
        if self.held.is_empty() && self.spill.is_empty() {
            match self.tx.try_send(item) {
                Ok(()) | Err(TrySendError::Closed(_)) => return,
                Err(TrySendError::Full(item)) => return self.replace_or_hold(item, same),
            }
        }
        self.replace_or_hold(item, same)
    }
    fn replace_or_hold(&mut self, item: T, same: impl Fn(&T, &T) -> bool) {
        if let Some(slot) = self.held.iter_mut().find(|q| same(q, &item)) {
            *slot = item;
            self.coalesced += 1;
        } else if self.hold(item).is_err() {
            self.coalesced += 1;
        }
    }
    #[cfg_attr(not(test), allow(dead_code))]
    pub fn held(&self) -> usize {
        self.held.len()
    }
    pub fn has_room(&self, spare: usize) -> bool {
        self.held.len() + self.spill.len() + spare <= self.cap
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::sync::mpsc;

    #[test]
    fn flood_never_loses_required_items_and_memory_stays_bounded() {
        let (tx, mut rx) = mpsc::channel::<u32>(8);
        let mut o = Outbox::new(tx, 32);
        let mut kept = Vec::new();
        for i in 0..1000u32 {
            // A producer obeying backpressure retries the refused item later.
            if o.push(i).is_ok() {
                kept.push(i);
            } else {
                break;
            }
        }
        assert_eq!(kept.len(), 8 + 32, "channel plus holdback, nothing more");
        assert!(!o.has_room(1));
        let mut got = Vec::new();
        while got.len() < kept.len() {
            while let Ok(v) = rx.try_recv() {
                got.push(v);
            }
            o.flush();
        }
        assert_eq!(got, kept, "every accepted item delivered, in order");
    }

    #[test]
    fn required_items_spill_instead_of_being_dropped() {
        let (tx, mut rx) = mpsc::channel::<u32>(1);
        let mut o = Outbox::new(tx, 2);
        for i in 0..50 {
            o.push_required(i);
        }
        assert_eq!(o.held(), 2);
        assert_eq!(o.spilled(), 47);
        let mut got = Vec::new();
        while got.len() < 50 {
            while let Ok(v) = rx.try_recv() {
                got.push(v);
            }
            o.flush();
        }
        assert_eq!(got, (0..50).collect::<Vec<_>>());
    }

    #[test]
    fn slow_consumer_coalesces_only_disposable_updates() {
        let (tx, mut rx) = mpsc::channel::<(u8, u32)>(2);
        let mut o = Outbox::new(tx, 4);
        // Required items (kind 1) are kept; snapshots (kind 0) replace one another.
        for i in 0..100u32 {
            o.push_or_replace((0, i), |a, b| a.0 == b.0 && b.0 == 0);
        }
        assert!(o.held() <= 4);
        assert!(o.coalesced > 0);
        o.push_required((1, 7));
        o.push_required((1, 8));
        let mut got = Vec::new();
        for _ in 0..50 {
            while let Ok(v) = rx.try_recv() {
                got.push(v);
            }
            o.flush();
        }
        assert!(got.contains(&(1, 7)) && got.contains(&(1, 8)));
        assert_eq!(got.iter().rfind(|v| v.0 == 0).map(|v| v.1), Some(99));
    }
}
