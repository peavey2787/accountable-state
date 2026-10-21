//! Domain-separated SHA-256 commitments and ordered Merkle membership proofs.
//! Tree shape: pair adjacent leaves, duplicate the last at each odd-width level.
#![forbid(unsafe_code)]
use gv_core::{Digest, StateOpening};
use sha2::{Digest as _, Sha256};

fn hash(parts: &[&[u8]]) -> Digest {
    let mut h = Sha256::new();
    for p in parts {
        h.update(p);
    }
    h.finalize().into()
}

pub fn input_digest(data: &[u8]) -> Digest {
    hash(&[b"gv/input/v1\0", &(data.len() as u64).to_le_bytes(), data])
}

pub fn commit_state(opening: &StateOpening) -> Digest {
    hash(&[
        b"gv/state/v1\0",
        &opening.nonce,
        &(opening.bytes.len() as u64).to_le_bytes(),
        &opening.bytes,
    ])
}

pub fn commit_secret(label: &[u8], secret: &[u8], nonce: &Digest) -> Digest {
    hash(&[
        b"gv/secret/v1\0",
        &(label.len() as u32).to_le_bytes(),
        label,
        nonce,
        &(secret.len() as u64).to_le_bytes(),
        secret,
    ])
}

pub fn leaf_hash(data: &[u8]) -> Digest {
    hash(&[b"gv/leaf/v1\0", &(data.len() as u64).to_le_bytes(), data])
}

pub fn node_hash(left: &Digest, right: &Digest) -> Digest {
    hash(&[b"gv/node/v1\0", left, right])
}

fn finalized_root(top: Digest, len: u64) -> Digest {
    hash(&[b"gv/root/v1\0", &len.to_le_bytes(), &top])
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InclusionProof {
    pub index: u64,
    pub leaf_count: u64,
    pub siblings: Vec<Digest>,
}

/// The in-memory reference implementation is capped to prevent accidental DoS.
/// Production systems need storage-backed incremental frontiers and bounded readers.
pub const MAX_LOG_LEAVES: usize = 1_048_576;
pub const MAX_LEAF_BYTES: usize = 128 * 1024;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum MerkleError {
    LogFull,
    LeafTooLarge,
}

/// Maintains an ordered log. Duplicating the odd leaf is unambiguous because the
/// committed leaf count is checked during proof verification.
#[derive(Default, Debug, Clone)]
pub struct MerkleLog {
    leaves: Vec<Digest>,
}

impl MerkleLog {
    pub fn new() -> Self {
        Self::default()
    }
    pub fn len(&self) -> usize {
        self.leaves.len()
    }
    pub fn is_empty(&self) -> bool {
        self.leaves.is_empty()
    }
    pub fn append(&mut self, bytes: &[u8]) -> Result<usize, MerkleError> {
        if bytes.len() > MAX_LEAF_BYTES {
            return Err(MerkleError::LeafTooLarge);
        }
        if self.leaves.len() >= MAX_LOG_LEAVES {
            return Err(MerkleError::LogFull);
        }
        let index = self.leaves.len();
        self.leaves.push(leaf_hash(bytes));
        Ok(index)
    }
    pub fn root(&self) -> Digest {
        if self.leaves.is_empty() {
            return finalized_root(hash(&[b"gv/empty/v1\0"]), 0);
        }
        let mut level = self.leaves.clone();
        while level.len() > 1 {
            level = level
                .chunks(2)
                .map(|c| node_hash(&c[0], c.get(1).unwrap_or(&c[0])))
                .collect();
        }
        finalized_root(level[0], self.leaves.len() as u64)
    }
    pub fn proof(&self, index: usize) -> Option<InclusionProof> {
        if index >= self.leaves.len() {
            return None;
        }
        let mut level = self.leaves.clone();
        let mut i = index;
        let mut siblings = Vec::new();
        while level.len() > 1 {
            let other = i ^ 1;
            siblings.push(*level.get(other).unwrap_or(&level[i]));
            level = level
                .chunks(2)
                .map(|c| node_hash(&c[0], c.get(1).unwrap_or(&c[0])))
                .collect();
            i /= 2;
        }
        Some(InclusionProof {
            index: index as u64,
            leaf_count: self.leaves.len() as u64,
            siblings,
        })
    }
}

pub fn verify_membership(root: &Digest, bytes: &[u8], proof: &InclusionProof) -> bool {
    if bytes.len() > MAX_LEAF_BYTES
        || proof.leaf_count == 0
        || proof.leaf_count > MAX_LOG_LEAVES as u64
        || proof.index >= proof.leaf_count
        || proof.siblings.len() > 20
    {
        return false;
    }
    let mut current = leaf_hash(bytes);
    let mut i = proof.index;
    let mut width = proof.leaf_count;
    let mut siblings = proof.siblings.iter();
    while width > 1 {
        let Some(sibling) = siblings.next() else {
            return false;
        };
        if i % 2 == 0 {
            // The omitted partner at the odd right edge must be the same hash.
            if i + 1 == width && sibling != &current {
                return false;
            }
            current = node_hash(&current, sibling);
        } else {
            current = node_hash(sibling, &current);
        }
        i /= 2;
        width = width.div_ceil(2);
    }
    siblings.next().is_none() && &finalized_root(current, proof.leaf_count) == root
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn inclusion_and_tampering() {
        for n in 1..20 {
            let mut tree = MerkleLog::new();
            for i in 0..n {
                tree.append(&[i as u8]).unwrap();
            }
            for i in 0..n {
                let p = tree.proof(i).unwrap();
                assert!(verify_membership(&tree.root(), &[i as u8], &p));
                assert!(!verify_membership(&tree.root(), &[200], &p));
            }
        }
    }
    #[test]
    fn independent_golden_root() {
        // Generated independently with Python hashlib, also checked with Node.
        let mut t = MerkleLog::new();
        t.append(b"alpha").unwrap();
        t.append(b"beta").unwrap();
        t.append(b"gamma").unwrap();
        assert_eq!(
            t.root(),
            [
                0xca, 0x37, 0xa1, 0x32, 0xe1, 0x26, 0x51, 0x41, 0x96, 0x4e, 0xbb, 0xfc, 0xac, 0x27,
                0x01, 0x45, 0x05, 0x3d, 0x8d, 0x75, 0x1f, 0x4a, 0x0f, 0x85, 0x5f, 0x0a, 0x2a, 0xb0,
                0x47, 0xf7, 0x9a, 0x11,
            ]
        );
    }
    #[test]
    fn count_binding() {
        let mut tree = MerkleLog::new();
        tree.append(b"x").unwrap();
        let root = tree.root();
        let mut p = tree.proof(0).unwrap();
        p.leaf_count = 2;
        assert!(!verify_membership(&root, b"x", &p));
    }
    #[test]
    fn oversized_leaf_rejected() {
        let mut log = MerkleLog::new();
        let oversized = vec![7u8; MAX_LEAF_BYTES + 1];
        assert_eq!(log.append(&oversized), Err(MerkleError::LeafTooLarge));
        assert_eq!(log.len(), 0);
    }
    #[test]
    fn excessive_and_truncated_proof_rejected() {
        let mut log = MerkleLog::new();
        for byte in 0..5 {
            log.append(&[byte]).unwrap();
        }
        let root = log.root();
        let mut proof = log.proof(3).unwrap();
        assert!(verify_membership(&root, &[3], &proof));
        proof.siblings.push([0; 32]);
        assert!(!verify_membership(&root, &[3], &proof));
        proof.siblings.clear();
        assert!(!verify_membership(&root, &[3], &proof));
        let mut proof = log.proof(3).unwrap();
        proof.leaf_count = u64::MAX;
        assert!(!verify_membership(&root, &[3], &proof));
    }
    #[test]
    fn odd_level_forgery_rejected() {
        let mut tree = MerkleLog::new();
        for i in 0..3 {
            tree.append(&[i]).unwrap();
        }
        let mut p = tree.proof(2).unwrap();
        p.siblings[0] = [42; 32];
        assert!(!verify_membership(&tree.root(), &[2], &p));
    }
}
