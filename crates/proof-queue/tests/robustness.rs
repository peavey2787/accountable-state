//! Hostile input: no verifier, decoder or ledger may panic or accuse on bytes they cannot parse.
//! Deterministic pseudo-random inputs so the test runs the same everywhere (the libFuzzer target
//! in `fuzz/` explores further).
use gv_edge::quorum::WitnessSet;
use gv_proof_queue::record::Record;
use gv_proof_queue::verify::{
    pack, unpack, Commitments, Equivocation, RecoveryCertificates, SignedInputs,
    TransitionVerifier, Verifier,
};
use gv_proof_queue::{Family, JobSpec, Ledger, Outcome, Priority};
use gv_sig::SigningKey;

struct Rng(u64);

impl Rng {
    fn next(&mut self) -> u64 {
        self.0 ^= self.0 << 13;
        self.0 ^= self.0 >> 7;
        self.0 ^= self.0 << 17;
        self.0
    }
    fn bytes(&mut self, max: usize) -> Vec<u8> {
        let n = (self.next() % (max as u64 + 1)) as usize;
        (0..n).map(|_| self.next() as u8).collect()
    }
}

fn spec(family: Family, payload: Vec<u8>) -> JobSpec {
    JobSpec {
        family,
        match_id: [1; 32],
        payload,
        priority: Priority::Low,
        deadline: None,
        deps: vec![],
    }
}

fn never_a_violation(v: &dyn Verifier, rng: &mut Rng, rounds: usize) {
    for _ in 0..rounds {
        let raw = rng.bytes(300);
        let packed = pack(&[raw.clone(), rng.bytes(64)]);
        for payload in [raw, packed] {
            let out = v.verify(&spec(v.family(), payload));
            assert!(
                !matches!(
                    out,
                    Outcome::Violation { .. } | Outcome::Valid | Outcome::Certified
                ),
                "{:?} accepted noise: {out:?}",
                v.family()
            );
        }
    }
}

#[test]
fn verifiers_never_accept_or_accuse_on_random_bytes() {
    let ids: Vec<_> = (10..14u8)
        .map(|n| SigningKey::from_seed([n; 32]).id())
        .collect();
    let mut rng = Rng(0x9E37_79B9_7F4A_7C15);
    never_a_violation(&SignedInputs, &mut rng, 2000);
    never_a_violation(&Commitments, &mut rng, 2000);
    never_a_violation(&Equivocation { witnesses: None }, &mut rng, 2000);
    never_a_violation(
        &Equivocation {
            witnesses: WitnessSet::new(&ids),
        },
        &mut rng,
        500,
    );
    never_a_violation(
        &RecoveryCertificates {
            witnesses: WitnessSet::new(&ids).unwrap(),
        },
        &mut rng,
        2000,
    );
    never_a_violation(
        &TransitionVerifier {
            rules: gv_edge::testkit::GridRules,
        },
        &mut rng,
        2000,
    );
}

#[test]
fn pack_and_record_decoders_never_panic_and_pack_is_canonical() {
    let mut rng = Rng(0xD1B5_4A32_D192_ED03);
    for _ in 0..20_000 {
        let b = rng.bytes(200);
        if let Some(items) = unpack(&b) {
            let owned: Vec<Vec<u8>> = items.iter().map(|i| i.to_vec()).collect();
            assert_eq!(pack(&owned), b, "an accepted encoding re-encodes to itself");
        }
        let _ = Record::decode(&b);
        let _ = Ledger::decode(&b);
    }
}
