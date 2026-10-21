//! Export package tests: equivocation and audit paths, round trips, tampering, limits.
use crate::audit::{compare_authenticators, AuditLog, Evidence};
use crate::export::*;
use crate::testkit::GridRules;
use gv_replay::StateMachine as _;
use gv_sig::SigningKey;

const M: [u8; 32] = [7; 32];

fn setup() -> (
    SigningKey,
    SigningKey,
    [gv_core::PlayerId; 2],
    GridRules,
    TrustAnchor,
) {
    let a = SigningKey::from_seed([1; 32]);
    let b = SigningKey::from_seed([2; 32]);
    let mut roster = [a.id(), b.id()];
    roster.sort();
    let rules = GridRules::new(roster);
    let anchor = TrustAnchor {
        match_id: M,
        ruleset: rules.ruleset_hash(),
        roster,
    };
    (a, b, roster, rules, anchor)
}

/// Two heads signed for the same sequence number: the owner equivocated.
fn forked(owner: &SigningKey, rules: &GridRules) -> Evidence {
    let mut l1 = AuditLog::new(M, owner.id());
    let mut l2 = AuditLog::new(M, owner.id());
    for i in 0..4u64 {
        l1.append(1, i.to_le_bytes().to_vec()).unwrap();
        l2.append(1, i.to_le_bytes().to_vec()).unwrap();
    }
    l1.append(1, b"left".to_vec()).unwrap();
    l2.append(1, b"right".to_vec()).unwrap();
    let rs = rules.ruleset_hash();
    compare_authenticators(
        &l1.sign_authenticator(rs, owner),
        &l2.sign_authenticator(rs, owner),
        None,
    )
    .unwrap()
}

#[test]
fn equivocation_package_round_trips_and_resists_tampering() {
    let (a, _b, roster, rules, anchor) = setup();
    let ev = forked(&a, &rules);
    let pkg = export_fraud(
        &rules,
        M,
        roster,
        FraudWitness::Equivocation(&ev),
        DisclosurePolicy::PUBLIC,
    )
    .unwrap();
    let bytes = pkg.encode().unwrap();
    assert_eq!(pkg.encode().unwrap(), bytes, "deterministic encoding");
    let (c, v) = verify_package(&bytes, &anchor, &rules).unwrap();
    assert_eq!(
        v,
        Verified::Fraud {
            kind: FraudKind::Equivocation,
            accused: a.id()
        }
    );
    assert_eq!(c.id, pkg.id());
    for i in (0..bytes.len()).step_by(bytes.len() / 211 + 1) {
        let mut t = bytes.clone();
        t[i] ^= 0x40;
        assert!(
            verify_package(&t, &anchor, &rules).is_err(),
            "flip at {i} accepted"
        );
    }
    // Another match, another roster and a truncation never verify.
    let mut other = anchor;
    other.match_id[0] ^= 1;
    assert_eq!(
        verify_package(&bytes, &other, &rules).unwrap_err(),
        ExportError::WrongContext
    );
    assert!(verify_package(&bytes[..bytes.len() - 1], &anchor, &rules).is_err());
}

#[test]
fn a_non_violation_does_not_export_as_fraud() {
    let (a, _b, roster, rules, anchor) = setup();
    // Two authenticators of the same honest log, one an extension of the other: no conflict.
    let mut log = AuditLog::new(M, a.id());
    log.append(1, vec![1]).unwrap();
    let first = log.sign_authenticator(rules.ruleset_hash(), &a);
    log.append(1, vec![2]).unwrap();
    let second = log.sign_authenticator(rules.ruleset_hash(), &a);
    let ev = Evidence::ConflictingAuthenticators(first, second);
    let pkg = export_fraud(
        &rules,
        M,
        roster,
        FraudWitness::Equivocation(&ev),
        DisclosurePolicy::PUBLIC,
    )
    .unwrap();
    assert_eq!(
        verify_package(&pkg.encode().unwrap(), &anchor, &rules).unwrap_err(),
        ExportError::NotAViolation
    );
}

#[test]
fn audit_package_with_history_verifies_and_rejects_unlinked_records() {
    let (a, b, roster, rules, anchor) = setup();
    let rs = rules.ruleset_hash();
    let mut log = AuditLog::new(M, a.id());
    for i in 0..6u64 {
        log.append(1, i.to_le_bytes().to_vec()).unwrap();
    }
    let head = log.sign_authenticator(rs, &a);
    let seg = log.segment(0, 6).unwrap();
    let ev = forked(&b, &rules);
    let audit = AuditExport {
        authenticators: vec![head.clone()],
        segments: vec![seg.clone()],
        evidence: vec![ev],
        ..Default::default()
    };
    let pkg = export_audit(&rules, M, roster, &audit, DisclosurePolicy::PUBLIC).unwrap();
    let bytes = pkg.encode().unwrap();
    let (_, v) = verify_package(&bytes, &anchor, &rules).unwrap();
    assert_eq!(
        v,
        Verified::Audit {
            authenticators: 1,
            segments: 1,
            challenges: 0,
            responses: 0,
            proven: vec![b.id()]
        }
    );
    // A segment that does not chain to a signed head in the export is refused.
    let orphan = AuditExport {
        segments: vec![seg],
        ..Default::default()
    };
    let pkg = export_audit(&rules, M, roster, &orphan, DisclosurePolicy::PUBLIC).unwrap();
    assert_eq!(
        verify_package(&pkg.encode().unwrap(), &anchor, &rules).unwrap_err(),
        ExportError::Invalid
    );
    // The item cap is enforced on export.
    let many = AuditExport {
        authenticators: vec![head; MAX_AUDIT_ITEMS + 1],
        ..Default::default()
    };
    assert_eq!(
        export_audit(&rules, M, roster, &many, DisclosurePolicy::PUBLIC)
            .and_then(|p| p.encode())
            .unwrap_err(),
        ExportError::TooLarge
    );
}

#[test]
fn commitments_never_claim_fraud_and_decode_strictly() {
    let (a, _b, roster, rules, _anchor) = setup();
    let ev = forked(&a, &rules);
    let pkg = export_fraud(
        &rules,
        M,
        roster,
        FraudWitness::Equivocation(&ev),
        DisclosurePolicy::PUBLIC,
    )
    .unwrap();
    let c = pkg.commitment();
    let enc = c.encode();
    assert_eq!(enc.len(), Commitment::WIRE_SIZE);
    assert_eq!(Commitment::decode(&enc).unwrap(), c);
    for i in 0..enc.len() {
        let mut t = enc.clone();
        t[i] ^= 1;
        assert!(
            Commitment::decode(&t).map(|d| d != c).unwrap_or(true),
            "flip at {i}"
        );
    }
    assert!(Commitment::decode(&enc[..enc.len() - 1]).is_err());
    // The commitment byte that says "publication only" cannot be cleared.
    let mut cleared = enc.clone();
    cleared[26 + 3] = 0;
    assert!(Commitment::decode(&cleared).is_err());
}
