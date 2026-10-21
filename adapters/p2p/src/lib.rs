//! Transport-agnostic P2P messages. There is intentionally no network stack yet.
#![forbid(unsafe_code)]
pub mod reliable;
use gv_core::{Digest, MatchId};

#[derive(Clone, Debug)]
pub struct Envelope {
    pub match_id: MatchId,
    pub sequence: u64,
    pub topic: Topic,
    pub message_digest: Digest,
    pub body: Vec<u8>,
}
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Topic {
    Input,
    PackedInput,
    Checkpoint,
    Availability,
    Challenge,
    Evidence,
    Verdict,
}

/// Implementations must enforce authenticated sender identity, frame bounds,
/// per-peer quotas, and duplicate suppression. See docs/08-p2p-consensus.md.
pub trait GossipTransport {
    type Error;
    fn publish(&mut self, msg: Envelope) -> Result<(), Self::Error>;
}

/// Transport-agnostic authenticated packed-control container. The outer sender
/// authentication, admission receipt and network anti-replay are still caller duties.
pub fn pack_controls(
    input: &gv_codec::SignedPackedControls,
) -> Result<Envelope, gv_codec::CodecError> {
    let body = input.encode()?;
    let message_digest = input.digest()?;
    Ok(Envelope {
        match_id: input.record.match_id,
        sequence: input.record.start_tick,
        topic: Topic::PackedInput,
        message_digest,
        body,
    })
}

pub fn unpack_controls(
    envelope: &Envelope,
) -> Result<gv_codec::SignedPackedControls, gv_codec::CodecError> {
    if envelope.topic != Topic::PackedInput {
        return Err(gv_codec::CodecError::InvalidVersion);
    }
    let decoded = gv_codec::SignedPackedControls::decode(&envelope.body)?;
    if decoded.record.match_id != envelope.match_id
        || decoded.record.start_tick != envelope.sequence
        || decoded.digest()? != envelope.message_digest
    {
        return Err(gv_codec::CodecError::ChainMismatch);
    }
    Ok(decoded)
}

#[cfg(test)]
mod tests {
    use super::*;
    use gv_codec::PackedControls;
    use gv_sig::SigningKey;
    #[test]
    fn envelope_binds_payload_and_session() {
        let key = SigningKey::from_seed([3; 32]);
        let signed = gv_codec::SignedPackedControls::sign(
            PackedControls {
                match_id: [5; 32],
                player: key.id(),
                previous_batch_hash: [6; 32],
                start_tick: 10,
                tick_count: 60,
                control_bytes: 1,
                initial_state: 1,
                changes: vec![],
            },
            &key,
        )
        .unwrap();
        let mut e = pack_controls(&signed).unwrap();
        assert_eq!(unpack_controls(&e).unwrap(), signed);
        e.match_id = [9; 32];
        assert_eq!(
            unpack_controls(&e),
            Err(gv_codec::CodecError::ChainMismatch)
        );
    }
}

#[cfg(feature = "native")]
pub mod native;
