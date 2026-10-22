//! Signed objects of the head register: what an owner claims, what a witness promises and
//! receipts, and the certificate that proves a quorum stored a claim.
use super::set::{Ballot, WitnessSet, MAX_WITNESSES};
use crate::audit::log::Reader;
use crate::audit::Authenticator;
use gv_core::{Digest, MatchId, ParticipantId};
use gv_sig::{Signature, SigningKey, SIG_LEN};
use sha2::{Digest as _, Sha256};

const CLAIM_LABEL: &str = "gv/quorum/claim/v1";
const RECOVER_LABEL: &str = "gv/quorum/recover/v1";
const PROMISE_LABEL: &str = "gv/quorum/promise/v1";
const RECEIPT_LABEL: &str = "gv/quorum/receipt/v1";
const NACK_LABEL: &str = "gv/quorum/nack/v1";

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum QuorumError {
    Malformed,
    BadSignature,
    WrongMatch,
    NotAWitness,
    /// Fewer distinct witness receipts than a quorum.
    Insufficient,
    /// A receipt or promise that does not belong to the claim it accompanies.
    Mismatch,
}

fn sig(r: &mut Reader<'_>) -> Result<Signature, QuorumError> {
    let b = r.bytes(SIG_LEN).map_err(|_| QuorumError::Malformed)?;
    Signature::from_slice(b).map_err(|_| QuorumError::Malformed)
}
fn take<const N: usize>(r: &mut Reader<'_>) -> Result<[u8; N], QuorumError> {
    r.take().map_err(|_| QuorumError::Malformed)
}
fn check(
    signer: &ParticipantId,
    label: &str,
    body: &[u8],
    s: &Signature,
) -> Result<(), QuorumError> {
    gv_sig::verify(signer, label, body, s).map_err(|_| QuorumError::BadSignature)
}

/// "Under `ballot` my log head is `auth`, and every signed batch or checkpoint I release ends
/// at or before `through_tick`." Signed by the owner; stored by witnesses before anything it
/// covers leaves the owner.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Claim {
    pub ballot: Ballot,
    pub auth: Authenticator,
    pub through_tick: u64,
    pub signature: Signature,
}

impl Claim {
    pub const WIRE: usize = Ballot::WIRE + Authenticator::WIRE_SIZE + 8 + SIG_LEN;
    fn body(ballot: &Ballot, auth: &Authenticator, through_tick: u64) -> Vec<u8> {
        let mut b = ballot.bytes().to_vec();
        b.extend_from_slice(&auth.encode());
        b.extend_from_slice(&through_tick.to_le_bytes());
        b
    }
    pub fn sign(ballot: Ballot, auth: Authenticator, through_tick: u64, key: &SigningKey) -> Self {
        let signature = key.sign(CLAIM_LABEL, &Self::body(&ballot, &auth, through_tick));
        Self {
            ballot,
            auth,
            through_tick,
            signature,
        }
    }
    pub fn owner(&self) -> ParticipantId {
        self.auth.owner
    }
    pub fn verify(&self) -> Result<(), QuorumError> {
        self.auth.verify().map_err(|_| QuorumError::BadSignature)?;
        check(
            &self.auth.owner,
            CLAIM_LABEL,
            &Self::body(&self.ballot, &self.auth, self.through_tick),
            &self.signature,
        )
    }
    /// What receipts commit to.
    pub fn digest(&self) -> Digest {
        let mut s = Sha256::new();
        s.update(b"gv/quorum/claim-digest/v1\0");
        s.update(Self::body(&self.ballot, &self.auth, self.through_tick));
        s.finalize().into()
    }
    pub fn encode(&self) -> Vec<u8> {
        let mut o = Self::body(&self.ballot, &self.auth, self.through_tick);
        o.extend_from_slice(self.signature.as_bytes());
        o
    }
    pub fn decode(b: &[u8]) -> Result<Self, QuorumError> {
        if b.len() != Self::WIRE {
            return Err(QuorumError::Malformed);
        }
        let mut r = Reader(b);
        let ballot = Ballot::from_bytes(take(&mut r)?);
        let auth = Authenticator::decode(
            r.bytes(Authenticator::WIRE_SIZE)
                .map_err(|_| QuorumError::Malformed)?,
        )
        .map_err(|_| QuorumError::Malformed)?;
        Ok(Self {
            ballot,
            auth,
            through_tick: u64::from_le_bytes(take(&mut r)?),
            signature: sig(&mut r)?,
        })
    }
}

/// The owner asks witnesses to promise nothing older than `ballot` and to report what they hold.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Recover {
    pub match_id: MatchId,
    pub owner: ParticipantId,
    pub ballot: Ballot,
    pub signature: Signature,
}

impl Recover {
    pub const WIRE: usize = 32 + 32 + Ballot::WIRE + SIG_LEN;
    fn body(m: &MatchId, o: &ParticipantId, b: &Ballot) -> Vec<u8> {
        let mut v = m.to_vec();
        v.extend_from_slice(o);
        v.extend_from_slice(&b.bytes());
        v
    }
    pub fn sign(match_id: MatchId, ballot: Ballot, key: &SigningKey) -> Self {
        let owner = key.id();
        let signature = key.sign(RECOVER_LABEL, &Self::body(&match_id, &owner, &ballot));
        Self {
            match_id,
            owner,
            ballot,
            signature,
        }
    }
    pub fn verify(&self) -> Result<(), QuorumError> {
        check(
            &self.owner,
            RECOVER_LABEL,
            &Self::body(&self.match_id, &self.owner, &self.ballot),
            &self.signature,
        )
    }
    pub fn encode(&self) -> Vec<u8> {
        let mut o = Self::body(&self.match_id, &self.owner, &self.ballot);
        o.extend_from_slice(self.signature.as_bytes());
        o
    }
    pub fn decode(b: &[u8]) -> Result<Self, QuorumError> {
        if b.len() != Self::WIRE {
            return Err(QuorumError::Malformed);
        }
        let mut r = Reader(b);
        Ok(Self {
            match_id: take(&mut r)?,
            owner: take(&mut r)?,
            ballot: Ballot::from_bytes(take(&mut r)?),
            signature: sig(&mut r)?,
        })
    }
}

/// A witness answer to [`Recover`]: it will accept nothing below `ballot`, and this is the
/// claim it holds (the one with the highest ballot, then the highest sequence).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Promise {
    pub witness: ParticipantId,
    pub match_id: MatchId,
    pub owner: ParticipantId,
    pub ballot: Ballot,
    pub accepted: Option<Claim>,
    pub signature: Signature,
}

impl Promise {
    fn body(
        w: &ParticipantId,
        m: &MatchId,
        o: &ParticipantId,
        b: &Ballot,
        accepted: Option<&Claim>,
    ) -> Vec<u8> {
        let mut v = w.to_vec();
        v.extend_from_slice(m);
        v.extend_from_slice(o);
        v.extend_from_slice(&b.bytes());
        match accepted {
            Some(c) => {
                v.push(1);
                v.extend_from_slice(&c.digest());
            }
            None => v.push(0),
        }
        v
    }
    pub fn sign(
        match_id: MatchId,
        owner: ParticipantId,
        ballot: Ballot,
        accepted: Option<Claim>,
        key: &SigningKey,
    ) -> Self {
        let witness = key.id();
        let signature = key.sign(
            PROMISE_LABEL,
            &Self::body(&witness, &match_id, &owner, &ballot, accepted.as_ref()),
        );
        Self {
            witness,
            match_id,
            owner,
            ballot,
            accepted,
            signature,
        }
    }
    pub fn verify(&self) -> Result<(), QuorumError> {
        check(
            &self.witness,
            PROMISE_LABEL,
            &Self::body(
                &self.witness,
                &self.match_id,
                &self.owner,
                &self.ballot,
                self.accepted.as_ref(),
            ),
            &self.signature,
        )?;
        if let Some(c) = &self.accepted {
            c.verify()?;
            if c.owner() != self.owner || c.auth.match_id != self.match_id {
                return Err(QuorumError::Mismatch);
            }
        }
        Ok(())
    }
    pub fn encode(&self) -> Vec<u8> {
        // The signed body carries only the claim digest; the claim follows the signature.
        let mut o = Self::body(
            &self.witness,
            &self.match_id,
            &self.owner,
            &self.ballot,
            self.accepted.as_ref(),
        );
        o.extend_from_slice(self.signature.as_bytes());
        if let Some(c) = &self.accepted {
            o.extend_from_slice(&c.encode());
        }
        o
    }
    pub fn decode(b: &[u8]) -> Result<Self, QuorumError> {
        let mut r = Reader(b);
        let witness = take(&mut r)?;
        let match_id = take(&mut r)?;
        let owner = take(&mut r)?;
        let ballot = Ballot::from_bytes(take(&mut r)?);
        let digest = match take::<1>(&mut r)?[0] {
            0 => None,
            1 => Some(take::<32>(&mut r)?),
            _ => return Err(QuorumError::Malformed),
        };
        let signature = sig(&mut r)?;
        let accepted = match digest {
            None => None,
            Some(d) => {
                let c = Claim::decode(r.bytes(Claim::WIRE).map_err(|_| QuorumError::Malformed)?)?;
                if c.digest() != d {
                    return Err(QuorumError::Mismatch);
                }
                Some(c)
            }
        };
        if !r.0.is_empty() {
            return Err(QuorumError::Malformed);
        }
        Ok(Self {
            witness,
            match_id,
            owner,
            ballot,
            accepted,
            signature,
        })
    }
}

/// "I durably stored this claim." A quorum of these commits it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Receipt {
    pub witness: ParticipantId,
    pub match_id: MatchId,
    pub owner: ParticipantId,
    pub claim: Digest,
    pub signature: Signature,
}

impl Receipt {
    pub const WIRE: usize = 32 * 4 + SIG_LEN;
    fn body(w: &ParticipantId, m: &MatchId, o: &ParticipantId, c: &Digest) -> Vec<u8> {
        let mut v = w.to_vec();
        v.extend_from_slice(m);
        v.extend_from_slice(o);
        v.extend_from_slice(c);
        v
    }
    pub fn sign(claim: &Claim, key: &SigningKey) -> Self {
        let witness = key.id();
        let (match_id, owner, digest) = (claim.auth.match_id, claim.owner(), claim.digest());
        let signature = key.sign(
            RECEIPT_LABEL,
            &Self::body(&witness, &match_id, &owner, &digest),
        );
        Self {
            witness,
            match_id,
            owner,
            claim: digest,
            signature,
        }
    }
    pub fn verify(&self) -> Result<(), QuorumError> {
        check(
            &self.witness,
            RECEIPT_LABEL,
            &Self::body(&self.witness, &self.match_id, &self.owner, &self.claim),
            &self.signature,
        )
    }
    pub fn encode(&self) -> Vec<u8> {
        let mut o = Self::body(&self.witness, &self.match_id, &self.owner, &self.claim);
        o.extend_from_slice(self.signature.as_bytes());
        o
    }
    pub fn decode(b: &[u8]) -> Result<Self, QuorumError> {
        if b.len() != Self::WIRE {
            return Err(QuorumError::Malformed);
        }
        let mut r = Reader(b);
        Ok(Self {
            witness: take(&mut r)?,
            match_id: take(&mut r)?,
            owner: take(&mut r)?,
            claim: take(&mut r)?,
            signature: sig(&mut r)?,
        })
    }
}

/// A witness refused: it has promised a newer ballot. Signed so that a single Byzantine witness
/// cannot fence an honest owner; fencing needs `f + 1` distinct signers.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Nack {
    pub witness: ParticipantId,
    pub match_id: MatchId,
    pub owner: ParticipantId,
    /// The ballot that was refused.
    pub refused: Ballot,
    pub promised: Ballot,
    pub signature: Signature,
}

impl Nack {
    pub const WIRE: usize = 32 * 3 + Ballot::WIRE * 2 + SIG_LEN;
    fn body(w: &ParticipantId, m: &MatchId, o: &ParticipantId, r: &Ballot, p: &Ballot) -> Vec<u8> {
        let mut v = w.to_vec();
        v.extend_from_slice(m);
        v.extend_from_slice(o);
        v.extend_from_slice(&r.bytes());
        v.extend_from_slice(&p.bytes());
        v
    }
    pub fn sign(
        match_id: MatchId,
        owner: ParticipantId,
        refused: Ballot,
        promised: Ballot,
        key: &SigningKey,
    ) -> Self {
        let witness = key.id();
        let signature = key.sign(
            NACK_LABEL,
            &Self::body(&witness, &match_id, &owner, &refused, &promised),
        );
        Self {
            witness,
            match_id,
            owner,
            refused,
            promised,
            signature,
        }
    }
    pub fn verify(&self) -> Result<(), QuorumError> {
        check(
            &self.witness,
            NACK_LABEL,
            &Self::body(
                &self.witness,
                &self.match_id,
                &self.owner,
                &self.refused,
                &self.promised,
            ),
            &self.signature,
        )
    }
    pub fn encode(&self) -> Vec<u8> {
        let mut o = Self::body(
            &self.witness,
            &self.match_id,
            &self.owner,
            &self.refused,
            &self.promised,
        );
        o.extend_from_slice(self.signature.as_bytes());
        o
    }
    pub fn decode(b: &[u8]) -> Result<Self, QuorumError> {
        if b.len() != Self::WIRE {
            return Err(QuorumError::Malformed);
        }
        let mut r = Reader(b);
        Ok(Self {
            witness: take(&mut r)?,
            match_id: take(&mut r)?,
            owner: take(&mut r)?,
            refused: Ballot::from_bytes(take(&mut r)?),
            promised: Ballot::from_bytes(take(&mut r)?),
            signature: sig(&mut r)?,
        })
    }
}

/// A claim plus a quorum of receipts: proof that the head was committed. Anyone holding the
/// pinned witness set can check it offline.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Certificate {
    pub claim: Claim,
    pub receipts: Vec<Receipt>,
}

impl Certificate {
    /// Distinct pinned witnesses with valid receipts for exactly this claim, at least a quorum.
    pub fn verify(&self, set: &WitnessSet) -> Result<(), QuorumError> {
        self.claim.verify()?;
        let digest = self.claim.digest();
        let mut seen: Vec<ParticipantId> = Vec::new();
        for r in &self.receipts {
            if !set.contains(&r.witness) {
                return Err(QuorumError::NotAWitness);
            }
            if r.claim != digest
                || r.owner != self.claim.owner()
                || r.match_id != self.claim.auth.match_id
            {
                return Err(QuorumError::Mismatch);
            }
            if seen.contains(&r.witness) {
                continue;
            }
            r.verify()?;
            seen.push(r.witness);
        }
        if seen.len() < set.quorum() {
            return Err(QuorumError::Insufficient);
        }
        Ok(())
    }
    pub fn encode(&self) -> Vec<u8> {
        let mut o = self.claim.encode();
        o.push(self.receipts.len() as u8);
        for r in &self.receipts {
            o.extend_from_slice(&r.encode());
        }
        o
    }
    pub fn decode(b: &[u8]) -> Result<Self, QuorumError> {
        let mut r = Reader(b);
        let claim = Claim::decode(r.bytes(Claim::WIRE).map_err(|_| QuorumError::Malformed)?)?;
        let n = take::<1>(&mut r)?[0] as usize;
        if n > MAX_WITNESSES {
            return Err(QuorumError::Malformed);
        }
        let mut receipts = Vec::with_capacity(n);
        for _ in 0..n {
            receipts.push(Receipt::decode(
                r.bytes(Receipt::WIRE).map_err(|_| QuorumError::Malformed)?,
            )?);
        }
        if !r.0.is_empty() {
            return Err(QuorumError::Malformed);
        }
        Ok(Self { claim, receipts })
    }
}

/// Messages of the register protocol. Owner to witness: `Recover`, `Store`, `HeldReq`;
/// witness to owner or peer: `Promise`, `Receipt`, `Nack`, `Held`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum QuorumMsg {
    Recover(Recover),
    Store(Claim),
    Promise(Promise),
    Receipt(Receipt),
    Nack(Nack),
    /// Ask a witness for the claim it holds for `owner` at `seq` and its receipt.
    HeldReq {
        owner: ParticipantId,
        seq: u64,
    },
    Held {
        claim: Claim,
        receipt: Receipt,
    },
}

impl QuorumMsg {
    pub fn encode(&self) -> Vec<u8> {
        let (tag, body): (u8, Vec<u8>) = match self {
            Self::Recover(m) => (1, m.encode()),
            Self::Store(m) => (2, m.encode()),
            Self::Promise(m) => (3, m.encode()),
            Self::Receipt(m) => (4, m.encode()),
            Self::Nack(m) => (5, m.encode()),
            Self::HeldReq { owner, seq } => {
                let mut v = owner.to_vec();
                v.extend_from_slice(&seq.to_le_bytes());
                (6, v)
            }
            Self::Held { claim, receipt } => {
                let mut v = claim.encode();
                v.extend_from_slice(&receipt.encode());
                (7, v)
            }
        };
        let mut o = vec![tag];
        o.extend_from_slice(&body);
        o
    }
    pub fn decode(b: &[u8]) -> Result<Self, QuorumError> {
        let (tag, body) = b.split_first().ok_or(QuorumError::Malformed)?;
        Ok(match tag {
            1 => Self::Recover(Recover::decode(body)?),
            2 => Self::Store(Claim::decode(body)?),
            3 => Self::Promise(Promise::decode(body)?),
            4 => Self::Receipt(Receipt::decode(body)?),
            5 => Self::Nack(Nack::decode(body)?),
            6 => {
                let mut r = Reader(body);
                let owner = take(&mut r)?;
                let seq = u64::from_le_bytes(take(&mut r)?);
                if !r.0.is_empty() {
                    return Err(QuorumError::Malformed);
                }
                Self::HeldReq { owner, seq }
            }
            7 => {
                if body.len() != Claim::WIRE + Receipt::WIRE {
                    return Err(QuorumError::Malformed);
                }
                let (c, r) = body.split_at(Claim::WIRE);
                Self::Held {
                    claim: Claim::decode(c)?,
                    receipt: Receipt::decode(r)?,
                }
            }
            _ => return Err(QuorumError::Malformed),
        })
    }
}
