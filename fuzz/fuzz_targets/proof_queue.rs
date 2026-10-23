#![no_main]
use gv_edge::quorum::WitnessSet;
use gv_proof_queue::record::Record;
use gv_proof_queue::verify::{
    unpack, Commitments, Equivocation, RecoveryCertificates, SignedInputs, Verifier,
};
use gv_proof_queue::{JobSpec, Ledger, Priority};
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let _ = unpack(data);
    let _ = Record::decode(data);
    let _ = Ledger::decode(data);
    let witnesses = WitnessSet::new(&[[1; 32], [2; 32], [3; 32], [4; 32]]);
    let verifiers: [Box<dyn Verifier>; 4] = [
        Box::new(SignedInputs),
        Box::new(Commitments),
        Box::new(Equivocation { witnesses: None }),
        Box::new(RecoveryCertificates { witnesses: witnesses.unwrap() }),
    ];
    for v in &verifiers {
        let _ = v.verify(&JobSpec {
            family: v.family(),
            match_id: [0; 32],
            payload: data.to_vec(),
            priority: Priority::Low,
            deadline: None,
            deps: vec![],
        });
    }
});
