//! Shared canonical-wire helpers: minimal ULEB128 varints and bounded fixed reads.

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CodecError {
    InvalidVersion,
    InvalidWidth,
    InvalidRange,
    InvalidChange,
    NonCanonical,
    TooLarge,
    Truncated,
    InvalidSignature,
    WrongSigner,
    Overflow,
    ChainMismatch,
}

pub(crate) fn push_varint(mut v: u32, out: &mut Vec<u8>) {
    while v >= 128 {
        out.push(((v as u8) & 0x7f) | 0x80);
        v >>= 7;
    }
    out.push(v as u8);
}

/// Strict reader: a longer-than-minimal encoding of the same value is `NonCanonical`.
pub(crate) fn read_varint(b: &[u8], pos: &mut usize) -> Result<u32, CodecError> {
    let begin = *pos;
    let mut value: u64 = 0;
    for i in 0..5 {
        let byte = *b.get(*pos).ok_or(CodecError::Truncated)?;
        *pos += 1;
        value |= u64::from(byte & 0x7f) << (7 * i);
        if byte & 0x80 == 0 {
            if value > u64::from(u32::MAX) {
                return Err(CodecError::Overflow);
            }
            let mut canonical = Vec::new();
            push_varint(value as u32, &mut canonical);
            if b[begin..*pos] != canonical[..] {
                return Err(CodecError::NonCanonical);
            }
            return Ok(value as u32);
        }
    }
    Err(CodecError::Overflow)
}

pub(crate) fn read_slice<'a>(
    b: &'a [u8],
    pos: &mut usize,
    n: usize,
) -> Result<&'a [u8], CodecError> {
    let end = pos.checked_add(n).ok_or(CodecError::Overflow)?;
    let src = b.get(*pos..end).ok_or(CodecError::Truncated)?;
    *pos = end;
    Ok(src)
}

pub(crate) fn read_array<const N: usize>(b: &[u8], pos: &mut usize) -> Result<[u8; N], CodecError> {
    read_slice(b, pos, N)?
        .try_into()
        .map_err(|_| CodecError::Truncated)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn varints_are_minimal_and_bounded() {
        let mut out = Vec::new();
        push_varint(179, &mut out);
        assert_eq!(out, [0xb3, 0x01]);
        assert_eq!(read_varint(&out, &mut 0), Ok(179));
        // b3 81 00 spells 179 in three bytes: forbidden.
        assert_eq!(
            read_varint(&[0xb3, 0x81, 0x00], &mut 0),
            Err(CodecError::NonCanonical)
        );
        assert_eq!(read_varint(&[0x80], &mut 0), Err(CodecError::Truncated));
        assert_eq!(
            read_varint(&[0xff, 0xff, 0xff, 0xff, 0x7f], &mut 0),
            Err(CodecError::Overflow)
        );
        assert_eq!(
            read_varint(&[0x80, 0x80, 0x80, 0x80, 0x80, 0x01], &mut 0),
            Err(CodecError::Overflow)
        );
    }
}
