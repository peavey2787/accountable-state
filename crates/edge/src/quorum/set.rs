//! The pinned witness set and the ballots that order recovery attempts.
use gv_core::ParticipantId;

pub const MAX_WITNESSES: usize = 31;

/// The witnesses a match pins. With `n` witnesses at most `f = (n - 1) / 3` may be Byzantine
/// (or lose their durable state); a quorum is `n - f` witnesses. Any two quorums share at least
/// `n - 2f >= f + 1` witnesses, so at least one honest witness lies in both.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct WitnessSet {
    ids: Vec<ParticipantId>,
}

impl WitnessSet {
    /// Sorted and deduplicated. `None` for an empty or oversized set.
    pub fn new(ids: &[ParticipantId]) -> Option<Self> {
        let mut ids = ids.to_vec();
        ids.sort_unstable();
        ids.dedup();
        (!ids.is_empty() && ids.len() <= MAX_WITNESSES).then_some(Self { ids })
    }
    pub fn ids(&self) -> &[ParticipantId] {
        &self.ids
    }
    pub fn len(&self) -> usize {
        self.ids.len()
    }
    pub fn is_empty(&self) -> bool {
        self.ids.is_empty()
    }
    pub fn contains(&self, id: &ParticipantId) -> bool {
        self.ids.binary_search(id).is_ok()
    }
    /// Byzantine witnesses tolerated.
    pub fn faults(&self) -> usize {
        (self.ids.len() - 1) / 3
    }
    /// Witnesses that must answer before a head is committed or a recovery may proceed.
    pub fn quorum(&self) -> usize {
        self.ids.len() - self.faults()
    }
    /// Distinct signed refusals that prove at least one honest witness saw a newer ballot.
    pub fn fence_threshold(&self) -> usize {
        self.faults() + 1
    }
}

/// Orders recovery attempts of one owner. `counter` rises with every attempt; `nonce` separates
/// two processes of the same owner that pick the same counter.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, PartialOrd, Ord)]
pub struct Ballot {
    pub counter: u64,
    pub nonce: u64,
}

impl Ballot {
    pub const WIRE: usize = 16;
    pub fn bytes(&self) -> [u8; Self::WIRE] {
        let mut b = [0u8; Self::WIRE];
        b[..8].copy_from_slice(&self.counter.to_le_bytes());
        b[8..].copy_from_slice(&self.nonce.to_le_bytes());
        b
    }
    pub fn from_bytes(b: [u8; Self::WIRE]) -> Self {
        let (c, n) = b.split_at(8);
        Self {
            counter: u64::from_le_bytes(c.try_into().unwrap_or([0; 8])),
            nonce: u64::from_le_bytes(n.try_into().unwrap_or([0; 8])),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ids(n: u8) -> Vec<ParticipantId> {
        (0..n).map(|i| [i + 1; 32]).collect()
    }

    #[test]
    fn quorums_always_intersect_in_an_honest_witness() {
        for n in 1..=MAX_WITNESSES {
            let set = WitnessSet::new(&ids(n as u8)).unwrap();
            let (f, q) = (set.faults(), set.quorum());
            assert!(n > 3 * f, "n={n}");
            // Two quorums overlap in at least f + 1 witnesses, more than the Byzantine bound.
            assert!(2 * q > n + f, "n={n} f={f} q={q}");
            assert!(
                q <= n - f,
                "a quorum must be reachable with f witnesses down"
            );
        }
    }

    #[test]
    fn empty_oversized_and_duplicate_sets() {
        assert!(WitnessSet::new(&[]).is_none());
        assert!(WitnessSet::new(&ids(32)).is_none());
        let dup = WitnessSet::new(&[[1; 32], [1; 32], [2; 32]]).unwrap();
        assert_eq!(dup.len(), 2);
    }

    #[test]
    fn ballots_order_by_counter_then_nonce() {
        let a = Ballot {
            counter: 1,
            nonce: 9,
        };
        let b = Ballot {
            counter: 2,
            nonce: 0,
        };
        assert!(a < b);
        assert!(
            Ballot {
                counter: 2,
                nonce: 1
            } > b
        );
        assert_eq!(Ballot::from_bytes(a.bytes()), a);
    }
}
