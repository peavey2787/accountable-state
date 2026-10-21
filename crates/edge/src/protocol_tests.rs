use super::*;
use crate::testkit::{self as grid, GridRules, GridState};
use gv_codec::{ControlChange, PackedControls, SignedPackedControls};
use gv_core::{Digest, PlayerId};
use gv_replay::StateMachine;
use gv_sig::SigningKey;

/// Deterministic blind for tests only; production draws 32 bytes from the OS CSPRNG.
fn test_blind(player: &PlayerId) -> Digest {
    *player
}
fn setup() -> (SigningKey, SigningKey, [PlayerId; 2], GridRules) {
    let a = SigningKey::from_seed([31; 32]);
    let b = SigningKey::from_seed([41; 32]);
    let mut roster = [a.id(), b.id()];
    roster.sort();
    let rules = GridRules::new(roster);
    (a, b, roster, rules)
}
fn batch(
    key: &SigningKey,
    match_id: Digest,
    start: u64,
    prev: Digest,
    initial: u16,
    sub: u16,
) -> SignedPackedControls {
    SignedPackedControls::sign(
        PackedControls {
            match_id,
            player: key.id(),
            previous_batch_hash: prev,
            start_tick: start,
            tick_count: 4,
            control_bytes: 1,
            initial_state: initial,
            changes: vec![ControlChange {
                offset: 1,
                state: sub,
            }],
        },
        key,
    )
    .unwrap()
}
fn certified_epoch(
    replica: &mut MatchReplica<GridRules>,
    a: &SigningKey,
    b: &SigningKey,
    mut pair: [SignedPackedControls; 2],
) -> CertifiedEpoch {
    let mut approval = BilateralAdmission::new(
        replica.match_id,
        replica.rules.ruleset_hash(),
        replica.previous_checkpoint(),
        replica.roster,
        replica.next_tick(),
        4,
    )
    .unwrap();
    for (key, item) in [(a, &pair[0]), (b, &pair[1])] {
        let commit = SignedBatchCommitment::sign(
            BatchCommitment::for_batch(
                item,
                replica.rules.ruleset_hash(),
                replica.previous_checkpoint(),
                &test_blind(&item.record.player),
            )
            .unwrap(),
            key,
        )
        .unwrap();
        assert_eq!(
            SignedBatchCommitment::decode(&commit.encode()).unwrap(),
            commit
        );
        approval.admit_commit(commit).unwrap();
    }
    assert_eq!(approval.ordered_reveals(), Err(AdmissionError::WrongPhase));
    for key in [a, b] {
        let lock = approval.sign_lock(key).unwrap();
        approval
            .admit_lock(SignedEpochLock::decode(&lock.encode()).unwrap())
            .unwrap();
    }
    pair.reverse();
    for item in pair {
        let blind = test_blind(&item.record.player);
        approval.admit_reveal(item, &blind).unwrap();
    }
    for item in approval.ordered_reveals().unwrap() {
        replica.admit(item).unwrap();
    }
    let mut signs = [
        replica.sign_candidate(a).unwrap(),
        replica.sign_candidate(b).unwrap(),
    ];
    signs.sort_by_key(|s| s.player);
    replica.finalize(signs).unwrap();
    CertifiedEpoch::from_accepted(replica.accepted().last().unwrap(), replica.roster).unwrap()
}
#[test]
fn two_peers_two_epochs_fraud_bundle_and_recovery() {
    let (alice, bob, roster, rules) = setup();
    let id = [13; 32];
    let mut p = MatchReplica::new(id, roster, rules.clone()).unwrap();
    let mut q = MatchReplica::new(id, roster, rules.clone()).unwrap();
    let epoch0 = [
        batch(
            &alice,
            id,
            0,
            [0; 32],
            grid::UP,
            if alice.id() == roster[0] {
                grid::RIGHT
            } else {
                grid::LEFT
            },
        ),
        batch(
            &bob,
            id,
            0,
            [0; 32],
            grid::UP,
            if bob.id() == roster[0] {
                grid::RIGHT
            } else {
                grid::LEFT
            },
        ),
    ];
    let first = certified_epoch(&mut p, &alice, &bob, epoch0.clone());
    let also = certified_epoch(&mut q, &alice, &bob, epoch0);
    // Hedged ML-DSA signatures differ run to run; the certified head must not.
    assert_eq!(first.checkpoint_hash(), also.checkpoint_hash());
    assert_eq!(p.state(), q.state());
    let state = GridState::decode(p.state()).unwrap();
    assert_eq!(state.walkers[0].y, -1);
    assert_eq!(state.walkers[1].y, -1);
    let epoch1 = [
        batch(
            &alice,
            id,
            4,
            p.next_batch_head(alice.id()).unwrap(),
            grid::ACT,
            0,
        ),
        batch(
            &bob,
            id,
            4,
            p.next_batch_head(bob.id()).unwrap(),
            grid::ACT,
            0,
        ),
    ];
    let second = certified_epoch(&mut p, &alice, &bob, epoch1.clone());
    certified_epoch(&mut q, &alice, &bob, epoch1);
    assert_eq!(p.state(), q.state());
    let after = GridState::decode(p.state()).unwrap();
    assert!(after.walkers.iter().all(|w| w.acts > 0));
    let accepted = CertifiedMatch {
        epochs: vec![first, second],
        disputes: vec![],
        live: false,
    };
    let archive = CertifiedMatch::decode(&accepted.encode().unwrap()).unwrap();
    let restored = archive.restore(id, roster, rules.clone()).unwrap();
    assert_eq!(restored.state(), p.state());
    assert_eq!(restored.next_tick(), 8);
    let mut wrong_id = id;
    wrong_id[0] ^= 1;
    assert!(archive.restore(wrong_id, roster, rules.clone()).is_err());
    let next_batches = [
        batch(
            &alice,
            id,
            8,
            p.next_batch_head(alice.id()).unwrap(),
            grid::ACT,
            0,
        ),
        batch(
            &bob,
            id,
            8,
            p.next_batch_head(bob.id()).unwrap(),
            grid::ACT,
            0,
        ),
    ];
    for item in next_batches {
        p.admit(item).unwrap();
    }
    let candidate = p.candidate().unwrap();
    let mut lie = candidate.checkpoint.clone();
    lie.next_state = [0x44; 32];
    let proof = FraudBundle {
        history: archive.clone(),
        allegation: CheckpointEvidence {
            trusted_previous_checkpoint: p.previous_checkpoint(),
            trusted_previous_state: candidate.checkpoint.previous_state,
            accused: SignedCheckpoint::sign(lie, &alice),
            previous_state: p.state().to_vec(),
            player_batches: candidate.batches.clone(),
            roster,
        },
    };
    assert_eq!(
        proof.verify(id, roster, rules.clone()),
        EvidenceVerdict::ProvenInvalidState
    );
    let bytes = proof.encode().unwrap();
    let recovered = FraudBundle::decode(&bytes).unwrap();
    assert_eq!(
        recovered.verify(id, roster, rules.clone()),
        EvidenceVerdict::ProvenInvalidState
    );
    {
        use crate::export::*;
        let anchor = TrustAnchor {
            match_id: id,
            ruleset: rules.ruleset_hash(),
            roster,
        };
        let public = DisclosurePolicy::PUBLIC;
        let secret = DisclosurePolicy {
            inputs_releasable: true,
            permanently_secret_state: true,
        };
        // Disclosure gate: no export of inputs under a secrecy policy.
        assert_eq!(
            export_fraud(
                &rules,
                id,
                roster,
                FraudWitness::FalseCheckpoint(&proof),
                secret
            )
            .unwrap_err(),
            ExportError::DisclosureForbidden
        );
        assert_eq!(
            export_match(&rules, id, roster, &archive, secret).unwrap_err(),
            ExportError::DisclosureForbidden
        );
        let pkg = export_fraud(
            &rules,
            id,
            roster,
            FraudWitness::FalseCheckpoint(&proof),
            public,
        )
        .unwrap();
        let bytes = pkg.encode().unwrap();
        // Round trip and deterministic id; commitment is publication-only and round-trips.
        assert_eq!(Package::decode(&bytes).unwrap().id(), pkg.id());
        let c = pkg.commitment();
        assert_eq!(Commitment::decode(&c.encode()).unwrap(), c);
        let (c2, v) = verify_package(&bytes, &anchor, &rules).unwrap();
        assert_eq!(c2, c);
        assert_eq!(
            v,
            Verified::Fraud {
                kind: FraudKind::FalseCheckpoint,
                accused: alice.id()
            }
        );
        // Wrong context is refused.
        let mut other = anchor;
        other.match_id[0] ^= 1;
        assert_eq!(
            verify_package(&bytes, &other, &rules).unwrap_err(),
            ExportError::WrongContext
        );
        // Any single-byte flip anywhere fails (sampled across the package).
        for i in (0..bytes.len()).step_by(bytes.len() / 97 + 1) {
            let mut t = bytes.clone();
            t[i] ^= 1;
            assert!(
                verify_package(&t, &anchor, &rules).is_err(),
                "flip at {i} accepted"
            );
        }
        assert!(verify_package(&bytes[..bytes.len() - 1], &anchor, &rules).is_err());
        let mut trailing = bytes.clone();
        trailing.push(0);
        assert!(verify_package(&trailing, &anchor, &rules).is_err());
        // Archive export verifies by replay and contains no secret material.
        let m = export_match(&rules, id, roster, &archive, public).unwrap();
        let (_, v) = verify_package(&m.encode().unwrap(), &anchor, &rules).unwrap();
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
        let a = export_audit(&rules, id, roster, &AuditExport::default(), public).unwrap();
        assert!(matches!(
            verify_package(&a.encode().unwrap(), &anchor, &rules)
                .unwrap()
                .1,
            Verified::Audit { .. }
        ));
    }
    let mut fake = proof.clone();
    fake.allegation.accused.signature = fake.allegation.accused.signature.with_bit_flipped(0);
    assert!(matches!(
        fake.verify(id, roster, rules.clone()),
        EvidenceVerdict::Inconclusive(_)
    ));
    let mut fake = proof.clone();
    fake.allegation.previous_state[0] ^= 1;
    assert!(matches!(
        fake.verify(id, roster, rules.clone()),
        EvidenceVerdict::Inconclusive(_)
    ));
    let mut fake = proof;
    fake.history.epochs.reverse();
    assert!(matches!(
        fake.verify(id, roster, rules),
        EvidenceVerdict::Inconclusive(_)
    ));
}
#[test]
fn commit_lock_reveal_rejects_adversaries() {
    let (alice, bob, roster, rules) = setup();
    let id = [5; 32];
    let a = batch(&alice, id, 0, [0; 32], grid::UP, grid::RIGHT);
    let b = batch(&bob, id, 0, [0; 32], grid::UP, grid::LEFT);
    let make = |signed: &SignedPackedControls, key: &SigningKey| {
        SignedBatchCommitment::sign(
            BatchCommitment::for_batch(
                signed,
                rules.ruleset_hash(),
                [0; 32],
                &test_blind(&signed.record.player),
            )
            .unwrap(),
            key,
        )
        .unwrap()
    };
    let signed_a = make(&a, &alice);
    let signed_b = make(&b, &bob);
    let mut ad = BilateralAdmission::new(id, rules.ruleset_hash(), [0; 32], roster, 0, 4).unwrap();
    assert_eq!(
        ad.admit_reveal(a.clone(), &test_blind(&a.record.player)),
        Err(AdmissionError::WrongPhase)
    );
    ad.admit_commit(signed_a.clone()).unwrap();
    assert_eq!(
        ad.admit_commit(signed_a.clone()),
        Err(AdmissionError::Duplicate)
    );
    let mut tampered = signed_b.clone();
    tampered.signature = tampered.signature.with_bit_flipped(0);
    assert_eq!(
        ad.admit_commit(tampered),
        Err(AdmissionError::InvalidSignature)
    );
    ad.admit_commit(signed_b).unwrap();
    let wrong = SignedEpochLock::sign([8; 32], &bob);
    assert_eq!(ad.admit_lock(wrong), Err(AdmissionError::Mismatch));
    ad.admit_lock(ad.sign_lock(&alice).unwrap()).unwrap();
    assert_eq!(
        ad.admit_reveal(a.clone(), &test_blind(&a.record.player)),
        Err(AdmissionError::WrongPhase)
    );
    ad.admit_lock(ad.sign_lock(&bob).unwrap()).unwrap();
    let changed = batch(&alice, id, 0, [0; 32], grid::DOWN, grid::LEFT);
    assert_eq!(
        ad.admit_reveal(changed.clone(), &test_blind(&changed.record.player)),
        Err(AdmissionError::Mismatch)
    );
    ad.admit_reveal(a.clone(), &test_blind(&a.record.player))
        .unwrap();
    ad.admit_reveal(b.clone(), &test_blind(&b.record.player))
        .unwrap();
    assert_eq!(
        ad.admit_reveal(a.clone(), &test_blind(&a.record.player)),
        Err(AdmissionError::Duplicate)
    );
    let alt = make(&changed, &alice);
    assert!(verify_equivocation(&signed_a, &alt));
    let mut bad = alt.clone();
    bad.signature = bad.signature.with_bit_flipped(0);
    assert!(!verify_equivocation(&signed_a, &bad));
}

#[test]
fn batch_commitments_are_hiding_and_binding_under_an_explicit_blind() {
    let (alice, _, roster, rules) = setup();
    let id = [5; 32];
    let a = batch(&alice, id, 0, [0; 32], grid::UP, grid::RIGHT);
    let commit = |blind: Digest| {
        BatchCommitment::for_batch(&a, rules.ruleset_hash(), [0; 32], &blind).unwrap()
    };
    // Same batch, different blinds: unlinkable commitments (hiding).
    assert_ne!(
        commit([1; 32]).blinded_batch_hash,
        commit([2; 32]).blinded_batch_hash
    );
    // The commitment is not the bare batch digest an attacker could grind over
    // the tiny control-word space.
    assert_ne!(commit([1; 32]).blinded_batch_hash, a.digest().unwrap());
    // Binding: a different batch under the same blind differs; wrong blind fails to open.
    let b2 = batch(&alice, id, 0, [0; 32], grid::DOWN, grid::RIGHT);
    assert_ne!(
        BatchCommitment::blind_batch(&b2, &[1; 32]).unwrap(),
        commit([1; 32]).blinded_batch_hash
    );
    let signed = SignedBatchCommitment::sign(commit([1; 32]), &alice).unwrap();
    let bob = SigningKey::from_seed([41; 32]);
    let other = batch(&bob, id, 0, [0; 32], grid::UP, grid::LEFT);
    let other_signed = SignedBatchCommitment::sign(
        BatchCommitment::for_batch(&other, rules.ruleset_hash(), [0; 32], &[9; 32]).unwrap(),
        &bob,
    )
    .unwrap();
    let mut ad = BilateralAdmission::new(id, rules.ruleset_hash(), [0; 32], roster, 0, 4).unwrap();
    ad.admit_commit(signed).unwrap();
    ad.admit_commit(other_signed).unwrap();
    ad.admit_lock(ad.sign_lock(&alice).unwrap()).unwrap();
    ad.admit_lock(ad.sign_lock(&bob).unwrap()).unwrap();
    assert_eq!(
        ad.admit_reveal(a.clone(), &[2; 32]),
        Err(AdmissionError::Mismatch)
    );
    ad.admit_reveal(a, &[1; 32]).unwrap();
}
#[test]
fn append_only_archive_is_byte_identical_to_a_full_encode() {
    let (alice, bob, roster, rules) = setup();
    let id = [91; 32];
    let mut replica = MatchReplica::new(id, roster, rules.clone()).unwrap();
    let mut full = CertifiedMatch {
        epochs: vec![],
        disputes: vec![],
        live: false,
    };
    let mut builder = super::ArchiveBuilder::new(&full).unwrap();
    assert_eq!(builder.as_bytes(), full.encode().unwrap().as_slice());
    let mut start = 0;
    for _ in 0..3 {
        let a = batch(
            &alice,
            id,
            start,
            replica.next_batch_head(alice.id()).unwrap(),
            grid::UP,
            0,
        );
        let b = batch(
            &bob,
            id,
            start,
            replica.next_batch_head(bob.id()).unwrap(),
            grid::UP,
            0,
        );
        let cert = certified_epoch(&mut replica, &alice, &bob, [a, b]);
        builder.push(&cert).unwrap();
        full.epochs.push(cert);
        start += 4;
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
