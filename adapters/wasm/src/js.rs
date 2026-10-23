//! The JavaScript-facing class: bytes in, bytes and JSON out.
use crate::host::HostQueue;
use js_sys::{Array, Uint8Array};
use wasm_bindgen::prelude::*;

fn bytes(v: &JsValue) -> Vec<u8> {
    Uint8Array::new(v).to_vec()
}

fn error(e: String) -> JsError {
    JsError::new(&e)
}

/// A proof queue for a Web Worker. Call `takeWrites()` after anything that may change the queue
/// and store the returned blobs (in order) before acknowledging the caller.
#[wasm_bindgen]
pub struct ProofQueue(HostQueue);

#[wasm_bindgen]
impl ProofQueue {
    /// `stored`: an array of Uint8Array blobs from earlier `takeWrites()` calls, oldest first.
    /// `witnesses`: the pinned witness keys, concatenated 32-byte ids (empty for none).
    #[wasm_bindgen(constructor)]
    pub fn new(
        stored: &Array,
        witnesses: &[u8],
        now: f64,
        outbox_limit: f64,
    ) -> Result<ProofQueue, JsError> {
        let stored: Vec<Vec<u8>> = stored.iter().map(|b| bytes(&b)).collect();
        let witnesses: Vec<[u8; 32]> = witnesses
            .chunks_exact(32)
            .filter_map(|c| c.try_into().ok())
            .collect();
        HostQueue::open(&stored, &witnesses, now as u64, outbox_limit as u64)
            .map(Self)
            .map_err(error)
    }

    pub fn submit(
        &self,
        family: u16,
        match_id: &[u8],
        payload: Vec<u8>,
        priority: u8,
        deadline: Option<f64>,
        now: f64,
    ) -> Result<Vec<u8>, JsError> {
        self.0
            .submit(
                family,
                match_id,
                payload,
                priority,
                deadline.map(|d| d as u64),
                now as u64,
            )
            .map(|id| id.to_vec())
            .map_err(error)
    }

    pub fn step(&self, now: f64) -> Result<usize, JsError> {
        self.0.step(now as u64).map_err(error)
    }

    /// The job's state code, or undefined for an unknown job.
    #[wasm_bindgen(js_name = jobState)]
    pub fn job_state(&self, id: &[u8]) -> Option<u8> {
        self.0.state(id)
    }

    #[wasm_bindgen(js_name = matchStatus)]
    pub fn match_status(&self, match_id: &[u8], required: &[u16]) -> Result<String, JsError> {
        self.0.match_status(match_id, required).map_err(error)
    }

    #[wasm_bindgen(js_name = eventsAfter)]
    pub fn events_after(&self, cursor: f64, limit: usize) -> String {
        self.0.events_after(cursor as u64, limit)
    }

    #[wasm_bindgen(js_name = takeWrites)]
    pub fn take_writes(&self) -> Array {
        self.0
            .take_writes()
            .iter()
            .map(|w| JsValue::from(Uint8Array::from(w.as_slice())))
            .collect()
    }
}
