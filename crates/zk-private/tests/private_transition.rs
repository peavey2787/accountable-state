//! A hidden ammunition count that may only go down by one per shot, with health unchanged.
//! Every check runs the real prover and verifier.
use gv_zk::{PublicClaim, ZkError, ZkVerifier};
use gv_zk_private::{
    advance, Context, IntType, Number, Op, PrivateTransitionVerifier, Program, Rule, State, Step,
};

const HEALTH: usize = 0;
const AMMO: usize = 1;

fn shot_program() -> Program {
    let rules = vec![
        Rule::Compare {
            field: HEALTH,
            op: Op::Eq,
        },
        Rule::Require {
            field: AMMO,
            op: Op::Ge,
            bound: 1u32.into(),
        },
        Rule::Sub {
            field: AMMO,
            delta: 1u32.into(),
        },
    ];
    Program::new(2, rules, 7).unwrap()
}

fn context(seed: u8) -> Context {
    Context {
        match_id: [seed; 32],
        manifest_hash: [2; 32],
        ruleset_hash: [3; 32],
        accepted_checkpoint_id: [4; 32],
        input_root: [5; 32],
    }
}

fn values(health: u32, ammo: u32) -> Vec<(IntType, Number)> {
    vec![(IntType::U32, health.into()), (IntType::U32, ammo.into())]
}

fn first_step() -> (Program, State, Step) {
    let program = shot_program();
    let genesis = State::genesis(&values(100, 5)).unwrap();
    let (next, step) = advance(&program, &context(1), &genesis, &values(100, 4)).unwrap();
    (program, next, step)
}

fn verifier() -> PrivateTransitionVerifier {
    PrivateTransitionVerifier::new(shot_program())
}

#[test]
fn a_rule_following_step_verifies_and_the_next_step_chains_from_it() {
    let (program, after_one, one) = first_step();
    assert_eq!(verifier().verify(&one.claim, &one.proof), Ok(()));

    let (_, two) = advance(&program, &context(1), &after_one, &values(100, 3)).unwrap();
    assert_eq!(verifier().verify(&two.claim, &two.proof), Ok(()));
    assert_eq!(
        two.claim.prior_root, one.claim.next_root,
        "steps chain by state root"
    );
}

#[test]
fn a_step_that_breaks_a_rule_cannot_be_proven() {
    let program = shot_program();
    let genesis = State::genesis(&values(100, 5)).unwrap();
    for wrong in [values(100, 5), values(100, 3), values(90, 4)] {
        assert!(advance(&program, &context(1), &genesis, &wrong).is_err());
    }
    let empty = State::genesis(&values(100, 0)).unwrap();
    assert!(advance(&program, &context(1), &empty, &values(100, 0)).is_err());
}

#[test]
fn a_proof_does_not_verify_for_a_different_public_claim() {
    let (_, _, step) = first_step();
    let swaps: [fn(&mut PublicClaim); 7] = [
        |c| c.match_id = [9; 32],
        |c| c.manifest_hash = [9; 32],
        |c| c.ruleset_hash = [9; 32],
        |c| c.accepted_checkpoint_id = [9; 32],
        |c| c.input_root = [9; 32],
        |c| c.violation_code += 1,
        |c| c.program_id = [9; 32],
    ];
    for swap in swaps {
        let mut claim = step.claim.clone();
        swap(&mut claim);
        assert_eq!(
            verifier().verify(&claim, &step.proof),
            Err(ZkError::Invalid)
        );
    }
}

#[test]
fn the_state_roots_must_be_the_proofs_commitment_lists() {
    let (_, _, step) = first_step();
    let mut claim = step.claim.clone();
    std::mem::swap(&mut claim.prior_root, &mut claim.next_root);
    assert_eq!(
        verifier().verify(&claim, &step.proof),
        Err(ZkError::Invalid)
    );
}

#[test]
fn a_damaged_or_truncated_proof_is_refused() {
    let (_, _, step) = first_step();
    for at in [0, 1, 5, step.proof.len() / 2, step.proof.len() - 1] {
        let mut bad = step.proof.clone();
        bad[at] ^= 0x01;
        assert_eq!(
            verifier().verify(&step.claim, &bad),
            Err(ZkError::Invalid),
            "byte {at}"
        );
    }
    for len in [0, 1, 40, step.proof.len() - 1] {
        assert_eq!(
            verifier().verify(&step.claim, &step.proof[..len]),
            Err(ZkError::Invalid)
        );
    }
    let mut long = step.proof.clone();
    long.push(0);
    assert_eq!(verifier().verify(&step.claim, &long), Err(ZkError::Invalid));
}

#[test]
fn a_verifier_for_other_rules_refuses_the_proof() {
    let (_, _, step) = first_step();
    let other = Program::new(
        2,
        vec![
            Rule::Compare {
                field: HEALTH,
                op: Op::Eq,
            },
            Rule::Add {
                field: AMMO,
                delta: 1u32.into(),
            },
        ],
        7,
    )
    .unwrap();
    let verifier = PrivateTransitionVerifier::new(other);
    assert_eq!(
        verifier.verify(&step.claim, &step.proof),
        Err(ZkError::Invalid)
    );
}

#[test]
fn programs_reject_bad_shapes() {
    let eq = |field| Rule::Compare { field, op: Op::Eq };
    assert!(Program::new(0, vec![eq(0)], 1).is_err());
    assert!(Program::new(2, vec![], 1).is_err());
    assert!(Program::new(2, vec![eq(2)], 1).is_err());
    assert!(Program::new(2, vec![eq(0); 8], 1).is_err());
    assert_ne!(
        Program::new(2, vec![eq(0)], 1).unwrap().id(),
        Program::new(2, vec![eq(0)], 2).unwrap().id()
    );
}
