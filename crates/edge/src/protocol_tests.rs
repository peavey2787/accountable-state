use super::*;
use crate::fixtures::{batch, certify, next_batches, Cast};
use crate::testkit::{self as grid, GridRules, GridState};
use gv_codec::SignedEventBatch;
use gv_core::{Digest, ParticipantId};
use gv_replay::StateMachine;
use gv_sig::SigningKey;

/// Deterministic blind for tests only; production draws 32 bytes from the OS CSPRNG.
fn test_blind(player: &ParticipantId) -> Digest {
    *player
}

fn commitment(
    rules: &GridRules,
    prev: Digest,
    b: &SignedEventBatch,
    key: &SigningKey,
) -> SignedBatchCommitment {
    SignedBatchCommitment::sign(
        BatchCommitment::for_batch(
            b,
            rules.ruleset_hash(),
            prev,
            &test_blind(&b.record.participant),
        )
        .unwrap(),
        key,
    )
    .unwrap()
}

/// Run one epoch through commit, lock and reveal, then certify it with every participant.
fn sealed_epoch(
    cast: &Cast,
    replica: &mut MatchReplica<GridRules>,
    inputs: Vec<Option<SignedEventBatch>>,
) -> CertifiedEpoch {
    let rules = replica.rules;
    let prev = replica.previous_checkpoint();
    let mut approval = EpochAdmission::new(
        cast.session.clone(),
        rules.ruleset_hash(),
        prev,
        replica.next_tick(),
        4,
    )
    .unwrap();
    for (key, item) in cast.keys.iter().zip(inputs.iter()) {
        let item = item.as_ref().unwrap();
        let commit = commitment(&rules, prev, item, key);
        assert_eq!(
            SignedBatchCommitment::decode(&commit.encode()).unwrap(),
            commit
        );
        approval.admit_commit(commit).unwrap();
    }
    assert_eq!(approval.ordered_reveals(), Err(AdmissionError::WrongPhase));
    for key in &cast.keys {
        let lock = approval.sign_lock(key).unwrap();
        approval
            .admit_lock(SignedEpochLock::decode(&lock.encode()).unwrap())
            .unwrap();
    }
    for item in inputs.into_iter().flatten().rev() {
        let blind = test_blind(&item.record.participant);
        approval.admit_reveal(item, &blind).unwrap();
    }
    certify(cast, replica, approval.ordered_reveals().unwrap())
}

#[test]
fn three_peers_two_epochs_fraud_bundle_and_recovery() {
    let cast = Cast::new(3, [13; 32]);
    let session = cast.session.clone();
    let id = session.match_id;
    let rules = GridRules;
    let mut p = cast.replica();
    let mut q = cast.replica();
    let epoch0: Vec<_> = cast
        .keys
        .iter()
        .map(|k| Some(batch(k, id, 0, [0; 32], grid::UP, grid::RIGHT)))
        .collect();
    let first = sealed_epoch(&cast, &mut p, epoch0.clone());
    let also = sealed_epoch(&cast, &mut q, epoch0);
    // Hedged ML-DSA signatures differ run to run; the certified head must not.
    assert_eq!(first.checkpoint_hash(), also.checkpoint_hash());
    assert_eq!(p.state(), q.state());
    let state = GridState::decode(p.state()).unwrap();
    assert!(state.walkers.iter().all(|(_, w)| w.y == -1));
    let next = next_batches(&cast, &p, grid::ACT, 0);
    let second = sealed_epoch(&cast, &mut p, next);
    let more = next_batches(&cast, &q, grid::ACT, 0);
    sealed_epoch(&cast, &mut q, more);
    assert_eq!(p.state(), q.state());
    let after = GridState::decode(p.state()).unwrap();
    assert!(after.walkers.iter().all(|(_, w)| w.acts > 0));
    let archive_src = CertifiedMatch {
        epochs: vec![first, second],
        disputes: vec![],
        live: false,
    };
    let archive = CertifiedMatch::decode(&archive_src.encode().unwrap()).unwrap();
    let restored = archive.restore(session.clone(), rules).unwrap();
    assert_eq!(restored.state(), p.state());
    assert_eq!(restored.next_tick(), 8);
    let mut other_session = session.clone();
    other_session.match_id[0] ^= 1;
    assert!(archive.restore(other_session, rules).is_err());
    for item in next_batches(&cast, &p, grid::ACT, 0).into_iter().flatten() {
        p.admit(item).unwrap();
    }
    let candidate = p.candidate().unwrap();
    let mut lie = candidate.checkpoint.clone();
    lie.next_state = [0x44; 32];
    let alice = &cast.keys[0];
    let proof = FraudBundle {
        history: archive.clone(),
        allegation: CheckpointEvidence {
            trusted_previous_checkpoint: p.previous_checkpoint(),
            trusted_previous_state: candidate.checkpoint.previous_state,
            accused: SignedCheckpoint::sign(lie, alice),
            previous_state: p.state().to_vec(),
            session: session.clone(),
            inputs: candidate.inputs.clone(),
        },
    };
    assert_eq!(
        proof.verify(session.clone(), rules),
        EvidenceVerdict::ProvenInvalidState
    );
    let recovered = FraudBundle::decode(&proof.encode().unwrap()).unwrap();
    assert_eq!(
        recovered.verify(session.clone(), rules),
        EvidenceVerdict::ProvenInvalidState
    );
    exports_verify_and_reject_tampering(&session, &rules, &archive, &proof, alice);
    let mut fake = proof.clone();
    fake.allegation.accused.signature = fake.allegation.accused.signature.with_bit_flipped(0);
    assert!(matches!(
        fake.verify(session.clone(), rules),
        EvidenceVerdict::Inconclusive(_)
    ));
    let mut fake = proof.clone();
    fake.allegation.previous_state[0] ^= 1;
    assert!(matches!(
        fake.verify(session.clone(), rules),
        EvidenceVerdict::Inconclusive(_)
    ));
    let mut fake = proof;
    fake.history.epochs.reverse();
    assert!(matches!(
        fake.verify(session, rules),
        EvidenceVerdict::Inconclusive(_)
    ));
}

fn exports_verify_and_reject_tampering(
    session: &gv_core::Session,
    rules: &GridRules,
    archive: &CertifiedMatch,
    proof: &FraudBundle,
    accused: &SigningKey,
) {
    use crate::export::*;
    let anchor = TrustAnchor {
        match_id: session.match_id,
        ruleset: rules.ruleset_hash(),
        session: session.digest(),
    };
    let public = DisclosurePolicy::PUBLIC;
    let secret = DisclosurePolicy {
        inputs_releasable: true,
        permanently_secret_state: true,
    };
    // Disclosure gate: no export of inputs under a secrecy policy.
    assert_eq!(
        export_fraud(rules, session, FraudWitness::FalseCheckpoint(proof), secret).unwrap_err(),
        ExportError::DisclosureForbidden
    );
    assert_eq!(
        export_match(rules, session, archive, secret).unwrap_err(),
        ExportError::DisclosureForbidden
    );
    let pkg = export_fraud(rules, session, FraudWitness::FalseCheckpoint(proof), public).unwrap();
    let bytes = pkg.encode().unwrap();
    assert_eq!(Package::decode(&bytes).unwrap().id(), pkg.id());
    let c = pkg.commitment();
    assert_eq!(Commitment::decode(&c.encode()).unwrap(), c);
    let (c2, v) = verify_package(&bytes, &anchor, rules).unwrap();
    assert_eq!(c2, c);
    assert_eq!(
        v,
        Verified::Fraud {
            kind: FraudKind::FalseCheckpoint,
            accused: accused.id()
        }
    );
    // Wrong context is refused.
    let mut other = anchor;
    other.match_id[0] ^= 1;
    assert_eq!(
        verify_package(&bytes, &other, rules).unwrap_err(),
        ExportError::WrongContext
    );
    let mut other = anchor;
    other.session[0] ^= 1;
    assert_eq!(
        verify_package(&bytes, &other, rules).unwrap_err(),
        ExportError::WrongContext
    );
    // Any single-byte flip anywhere fails (sampled across the package).
    for i in (0..bytes.len()).step_by(bytes.len() / 97 + 1) {
        let mut t = bytes.clone();
        t[i] ^= 1;
        assert!(
            verify_package(&t, &anchor, rules).is_err(),
            "flip at {i} accepted"
        );
    }
    assert!(verify_package(&bytes[..bytes.len() - 1], &anchor, rules).is_err());
    let mut trailing = bytes.clone();
    trailing.push(0);
    assert!(verify_package(&trailing, &anchor, rules).is_err());
    // Archive export verifies by replay and contains no secret material.
    let m = export_match(rules, session, archive, public).unwrap();
    let (_, v) = verify_package(&m.encode().unwrap(), &anchor, rules).unwrap();
    assert_eq!(
        v,
        Verified::Match {
            ticks: 8,
            epochs: 2,
            disputed: 0,
            segments: 1
        }
    );
    // Audit export: empty is valid and bounded.
    let a = export_audit(rules, session, &AuditExport::default(), public).unwrap();
    assert!(matches!(
        verify_package(&a.encode().unwrap(), &anchor, rules)
            .unwrap()
            .1,
        Verified::Audit { .. }
    ));
}

#[test]
fn commit_lock_reveal_rejects_adversaries() {
    let cast = Cast::new(3, [5; 32]);
    let rules = GridRules;
    let id = cast.session.match_id;
    let alice = &cast.keys[0];
    let bob = &cast.keys[1];
    let batches: Vec<_> = cast
        .keys
        .iter()
        .map(|k| batch(k, id, 0, [0; 32], grid::UP, grid::RIGHT))
        .collect();
    let a = batches[0].clone();
    let signed_a = commitment(&rules, [0; 32], &a, alice);
    let mut ad =
        EpochAdmission::new(cast.session.clone(), rules.ruleset_hash(), [0; 32], 0, 4).unwrap();
    assert_eq!(
        ad.admit_reveal(a.clone(), &test_blind(&alice.id())),
        Err(AdmissionError::WrongPhase)
    );
    ad.admit_commit(signed_a.clone()).unwrap();
    assert_eq!(
        ad.admit_commit(signed_a.clone()),
        Err(AdmissionError::Duplicate)
    );
    let signed_b = commitment(&rules, [0; 32], &batches[1], bob);
    let mut tampered = signed_b.clone();
    tampered.signature = tampered.signature.with_bit_flipped(0);
    assert_eq!(
        ad.admit_commit(tampered),
        Err(AdmissionError::InvalidSignature)
    );
    ad.admit_commit(signed_b).unwrap();
    let outsider = SigningKey::from_seed([99; 32]);
    let stranger = commitment(
        &rules,
        [0; 32],
        &batch(&outsider, id, 0, [0; 32], 0, 0),
        &outsider,
    );
    assert_eq!(ad.admit_commit(stranger), Err(AdmissionError::WrongSigner));
    let wrong = SignedEpochLock::sign([8; 32], bob);
    assert_eq!(ad.admit_lock(wrong), Err(AdmissionError::Mismatch));
    ad.admit_lock(ad.sign_lock(alice).unwrap()).unwrap();
    assert_eq!(
        ad.admit_reveal(a.clone(), &test_blind(&alice.id())),
        Err(AdmissionError::WrongPhase)
    );
    ad.admit_lock(ad.sign_lock(bob).unwrap()).unwrap();
    let changed = batch(alice, id, 0, [0; 32], grid::DOWN, grid::LEFT);
    assert_eq!(
        ad.admit_reveal(changed.clone(), &test_blind(&alice.id())),
        Err(AdmissionError::Mismatch)
    );
    ad.admit_reveal(a.clone(), &test_blind(&alice.id()))
        .unwrap();
    ad.admit_reveal(batches[1].clone(), &test_blind(&bob.id()))
        .unwrap();
    assert_eq!(
        ad.admit_reveal(a, &test_blind(&alice.id())),
        Err(AdmissionError::Duplicate)
    );
    let alt = commitment(&rules, [0; 32], &changed, alice);
    assert!(verify_equivocation(&signed_a, &alt));
    let mut bad = alt.clone();
    bad.signature = bad.signature.with_bit_flipped(0);
    assert!(!verify_equivocation(&signed_a, &bad));
}

#[test]
fn batch_commitments_are_hiding_and_binding_under_an_explicit_blind() {
    let cast = Cast::new(2, [5; 32]);
    let rules = GridRules;
    let id = cast.session.match_id;
    let (alice, bob) = (&cast.keys[0], &cast.keys[1]);
    let a = batch(alice, id, 0, [0; 32], grid::UP, grid::RIGHT);
    let commit = |blind: Digest| {
        BatchCommitment::for_batch(&a, rules.ruleset_hash(), [0; 32], &blind).unwrap()
    };
    // Same batch, different blinds: unlinkable commitments (hiding).
    assert_ne!(
        commit([1; 32]).blinded_batch_hash,
        commit([2; 32]).blinded_batch_hash
    );
    // The commitment is not the bare batch digest an attacker could grind over the tiny
    // control-word space.
    assert_ne!(commit([1; 32]).blinded_batch_hash, a.digest().unwrap());
    // Binding: a different batch under the same blind differs; a wrong blind fails to open.
    let b2 = batch(alice, id, 0, [0; 32], grid::DOWN, grid::RIGHT);
    assert_ne!(
        BatchCommitment::blind_batch(&b2, &[1; 32]).unwrap(),
        commit([1; 32]).blinded_batch_hash
    );
    let signed = SignedBatchCommitment::sign(commit([1; 32]), alice).unwrap();
    let other = batch(bob, id, 0, [0; 32], grid::UP, grid::LEFT);
    let other_signed = SignedBatchCommitment::sign(
        BatchCommitment::for_batch(&other, rules.ruleset_hash(), [0; 32], &[9; 32]).unwrap(),
        bob,
    )
    .unwrap();
    let mut ad =
        EpochAdmission::new(cast.session.clone(), rules.ruleset_hash(), [0; 32], 0, 4).unwrap();
    ad.admit_commit(signed).unwrap();
    ad.admit_commit(other_signed).unwrap();
    ad.admit_lock(ad.sign_lock(alice).unwrap()).unwrap();
    ad.admit_lock(ad.sign_lock(bob).unwrap()).unwrap();
    assert_eq!(
        ad.admit_reveal(a.clone(), &[2; 32]),
        Err(AdmissionError::Mismatch)
    );
    ad.admit_reveal(a, &[1; 32]).unwrap();
}

#[test]
fn append_only_archive_is_byte_identical_to_a_full_encode() {
    let cast = Cast::new(4, [91; 32]);
    let mut replica = cast.replica();
    let mut full = CertifiedMatch {
        epochs: vec![],
        disputes: vec![],
        live: false,
    };
    let mut builder = super::ArchiveBuilder::new(&full).unwrap();
    assert_eq!(builder.as_bytes(), full.encode().unwrap().as_slice());
    for _ in 0..3 {
        let inputs = next_batches(&cast, &replica, grid::UP, 0);
        let cert = sealed_epoch(&cast, &mut replica, inputs);
        builder.push(&cert).unwrap();
        full.epochs.push(cert);
        assert_eq!(
            builder.as_bytes(),
            full.encode().unwrap().as_slice(),
            "after {} epochs",
            full.epochs.len()
        );
    }
    let restored = CertifiedMatch::decode(builder.as_bytes()).unwrap();
    assert_eq!(restored.epochs.len(), 3);
}
