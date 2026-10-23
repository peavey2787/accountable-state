//! Aggregation: many canonical items in one job payload (`u32 count`, then `u32 len` + bytes each).
//! One job and one journal record instead of thousands.

/// Items in one aggregated payload.
pub const MAX_ITEMS: usize = 65_536;

pub fn pack<T: AsRef<[u8]>>(items: &[T]) -> Vec<u8> {
    let mut out = Vec::new();
    out.extend_from_slice(&(items.len() as u32).to_le_bytes());
    for item in items {
        let b = item.as_ref();
        out.extend_from_slice(&(b.len() as u32).to_le_bytes());
        out.extend_from_slice(b);
    }
    out
}

fn word(b: &[u8]) -> Option<(usize, &[u8])> {
    let (head, tail) = b.split_at_checked(4)?;
    Some((u32::from_le_bytes(head.try_into().ok()?) as usize, tail))
}

/// The items, or `None` unless the payload is exactly a well-formed pack.
pub fn unpack(payload: &[u8]) -> Option<Vec<&[u8]>> {
    let (count, mut rest) = word(payload)?;
    if count > MAX_ITEMS {
        return None;
    }
    let mut items = Vec::with_capacity(count.min(1024));
    for _ in 0..count {
        let (len, tail) = word(rest)?;
        let (item, tail) = tail.split_at_checked(len)?;
        items.push(item);
        rest = tail;
    }
    rest.is_empty().then_some(items)
}
