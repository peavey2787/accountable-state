//! The single replay engine. Live play, the provisional timeline, certification, fraud evidence
//! and offline verification all step the rules through these functions, so they cannot disagree.
use crate::machine::{RuleError, StateMachine, ViolationCode};
use gv_codec::EventBatch;
use gv_core::{Event, ParticipantId, Session};

/// Largest state any epoch may produce or start from.
pub const MAX_STATE_BYTES: usize = 65536;

/// A signed event the ruleset rejected as illegal. In live (sanitized) replay it is neutralized
/// so honest play cannot be stalled; this record, with the sender's batch signature, is the
/// portable proof of who sent what at which tick.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InputViolation {
    pub participant: ParticipantId,
    pub tick: u64,
    pub payload: Vec<u8>,
    pub code: ViolationCode,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ReplayError {
    /// Strict mode only: the rules deterministically rejected this event.
    Violation(InputViolation),
    /// The verifier or ruleset failed. Never evidence against a participant.
    Execution(String),
    StateTooLarge,
    /// The supplied batches do not fit the session, epoch or roster.
    Malformed,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Replayed {
    pub state: Vec<u8>,
    pub violations: Vec<InputViolation>,
}

fn bounded(state: Vec<u8>) -> Result<Vec<u8>, ReplayError> {
    if state.len() > MAX_STATE_BYTES {
        return Err(ReplayError::StateTooLarge);
    }
    Ok(state)
}

fn apply_event<M: StateMachine>(
    machine: &M,
    state: Vec<u8>,
    event: &Event,
    sanitize: bool,
    violations: &mut Vec<InputViolation>,
) -> Result<Vec<u8>, ReplayError> {
    let input = event.encode();
    match machine.apply(&state, &input) {
        Ok(next) => bounded(next),
        Err(RuleError::ExecutionFailure(e)) => Err(ReplayError::Execution(e)),
        Err(RuleError::InvalidAction(code)) => {
            let violation = InputViolation {
                participant: event.participant,
                tick: event.tick,
                payload: event.payload.to_vec(),
                code,
            };
            if !sanitize {
                return Err(ReplayError::Violation(violation));
            }
            violations.push(violation);
            match machine.neutralize(&input) {
                None => Ok(state),
                Some(neutral) => machine
                    .apply(&state, &neutral)
                    .map_err(|_| ReplayError::Execution("neutral input rejected".into()))
                    .and_then(bounded),
            }
        }
    }
}

/// One tick: every roster slot's events in the session's order, then the world update.
/// `inputs[slot]` are that participant's payloads for this tick, in application order.
pub fn step_tick<M: StateMachine>(
    machine: &M,
    session: &Session,
    mut state: Vec<u8>,
    tick: u64,
    inputs: &[Vec<&[u8]>],
    sanitize: bool,
    violations: &mut Vec<InputViolation>,
) -> Result<Vec<u8>, ReplayError> {
    if inputs.len() != session.roster.len() {
        return Err(ReplayError::Malformed);
    }
    for slot in session.ordering.order(&session.roster, tick) {
        let Some(participant) = session.roster.get(slot) else {
            return Err(ReplayError::Malformed);
        };
        for payload in &inputs[slot] {
            let event = Event {
                participant: participant.id,
                tick,
                payload,
            };
            state = apply_event(machine, state, &event, sanitize, violations)?;
        }
    }
    match machine.advance(&state, tick) {
        Ok(None) => Ok(state),
        Ok(Some(next)) => bounded(next),
        Err(RuleError::ExecutionFailure(e)) => Err(ReplayError::Execution(e)),
        Err(RuleError::InvalidAction(_)) => {
            Err(ReplayError::Execution("world update rejected".into()))
        }
    }
}

fn check_batches(
    session: &Session,
    start: u64,
    count: u32,
    batches: &[Option<&EventBatch>],
) -> Result<(), ReplayError> {
    if batches.len() != session.roster.len() || count == 0 {
        return Err(ReplayError::Malformed);
    }
    for (slot, batch) in batches.iter().enumerate() {
        let Some(batch) = batch else { continue };
        let allowed = session
            .roster
            .get(slot)
            .is_some_and(|p| p.id == batch.participant && p.role.submits());
        if !allowed
            || batch.match_id != session.match_id
            || batch.start_tick != start
            || batch.tick_count != count
        {
            return Err(ReplayError::Malformed);
        }
    }
    Ok(())
}

/// Replay one epoch. `batches` is indexed by roster slot; `None` is a participant who
/// contributed nothing this epoch (absent, or a spectator) and applies no events.
pub fn replay_epoch<M: StateMachine>(
    machine: &M,
    session: &Session,
    state: &[u8],
    start: u64,
    count: u32,
    batches: &[Option<&EventBatch>],
    sanitize: bool,
) -> Result<Replayed, ReplayError> {
    check_batches(session, start, count, batches)?;
    let mut state = bounded(state.to_vec())?;
    let mut violations = Vec::new();
    for offset in 0..count {
        let inputs = batches
            .iter()
            .map(|b| match b {
                Some(batch) => batch.events_at(offset).map_err(|_| ReplayError::Malformed),
                None => Ok(Vec::new()),
            })
            .collect::<Result<Vec<_>, _>>()?;
        let tick = start + u64::from(offset);
        state = step_tick(
            machine,
            session,
            state,
            tick,
            &inputs,
            sanitize,
            &mut violations,
        )?;
    }
    Ok(Replayed { state, violations })
}

#[cfg(test)]
mod tests {
    use super::*;
    use gv_codec::{EventBody, HeldChange, TickEvent};
    use gv_core::Digest;

    const ILLEGAL: u8 = 0xff;
    const BROKEN: u8 = 0xfe;

    /// State: one running total per roster slot of the bytes each participant sent, plus the
    /// number of world updates. Payload `0xff` is illegal; `0xfe` crashes the ruleset.
    struct Totals {
        slots: usize,
        neutral: bool,
    }
    impl Totals {
        fn slot_of(&self, input: &[u8]) -> usize {
            usize::from(input[0])
        }
    }
    impl StateMachine for Totals {
        fn ruleset_hash(&self) -> Digest {
            [1; 32]
        }
        fn genesis(&self, session: &Session) -> Vec<u8> {
            vec![0; session.roster.len() + 1]
        }
        fn apply(&self, state: &[u8], input: &[u8]) -> Result<Vec<u8>, RuleError> {
            let event =
                Event::decode(input).map_err(|_| RuleError::InvalidAction(ViolationCode(9)))?;
            let payload = *event.payload.first().unwrap_or(&0);
            match payload {
                ILLEGAL => Err(RuleError::InvalidAction(ViolationCode(1))),
                BROKEN => Err(RuleError::ExecutionFailure("boom".into())),
                p => {
                    let mut next = state.to_vec();
                    let slot = self.slot_of(&event.participant);
                    next[slot] = next[slot].wrapping_add(p);
                    Ok(next)
                }
            }
        }
        fn advance(&self, state: &[u8], _tick: u64) -> Result<Option<Vec<u8>>, RuleError> {
            let mut next = state.to_vec();
            next[self.slots] += 1;
            Ok(Some(next))
        }
        fn neutralize(&self, input: &[u8]) -> Option<Vec<u8>> {
            let event = Event::decode(input).ok()?;
            self.neutral.then(|| {
                Event {
                    payload: &[0],
                    ..event
                }
                .encode()
            })
        }
    }

    fn session(n: u8) -> Session {
        let ids: Vec<_> = (0..n).map(|i| [i; 32]).collect();
        Session::unanimous([5; 32], &ids).unwrap()
    }

    fn held(who: u8, payloads: &[(u32, u8)]) -> EventBatch {
        EventBatch {
            match_id: [5; 32],
            participant: [who; 32],
            previous_batch_hash: [0; 32],
            start_tick: 10,
            tick_count: 4,
            body: EventBody::Held {
                initial: vec![1],
                changes: payloads
                    .iter()
                    .map(|(offset, p)| HeldChange {
                        offset: *offset,
                        payload: vec![*p],
                    })
                    .collect(),
            },
        }
    }

    fn rules() -> Totals {
        Totals {
            slots: 3,
            neutral: true,
        }
    }

    #[test]
    fn three_participants_replay_deterministically_with_world_updates() {
        let session = session(3);
        let (a, b, c) = (held(0, &[]), held(1, &[(2, 5)]), held(2, &[]));
        let state = rules().genesis(&session);
        let out = replay_epoch(
            &rules(),
            &session,
            &state,
            10,
            4,
            &[Some(&a), Some(&b), Some(&c)],
            false,
        )
        .unwrap();
        // a: 1 x 4, b: 1,1,5,5, c: 1 x 4; four world updates.
        assert_eq!(out.state, vec![4, 12, 4, 4]);
        assert!(out.violations.is_empty());
        let again = replay_epoch(
            &rules(),
            &session,
            &state,
            10,
            4,
            &[Some(&a), Some(&b), Some(&c)],
            false,
        )
        .unwrap();
        assert_eq!(out, again);
    }

    #[test]
    fn absent_participants_apply_nothing() {
        let session = session(3);
        let a = held(0, &[]);
        let out = replay_epoch(
            &rules(),
            &session,
            &[0; 4],
            10,
            4,
            &[Some(&a), None, None],
            false,
        )
        .unwrap();
        assert_eq!(out.state, vec![4, 0, 0, 4]);
    }

    #[test]
    fn discrete_events_apply_only_where_listed() {
        let session = session(2);
        let mut a = held(0, &[]);
        a.body = EventBody::Discrete {
            events: vec![
                TickEvent {
                    offset: 1,
                    payload: vec![7],
                },
                TickEvent {
                    offset: 1,
                    payload: vec![2],
                },
            ],
        };
        let out = replay_epoch(
            &Totals {
                slots: 2,
                neutral: true,
            },
            &session,
            &[0; 3],
            10,
            4,
            &[Some(&a), None],
            false,
        )
        .unwrap();
        assert_eq!(out.state, vec![9, 0, 4]);
    }

    #[test]
    fn illegal_events_are_violations_strictly_and_neutralized_when_live() {
        let session = session(2);
        let (a, b) = (held(0, &[(1, ILLEGAL)]), held(1, &[]));
        let batches = [Some(&a), Some(&b)];
        let rules = Totals {
            slots: 2,
            neutral: true,
        };
        let strict = replay_epoch(&rules, &session, &[0; 3], 10, 4, &batches, false);
        let Err(ReplayError::Violation(v)) = strict else {
            panic!("strict replay must report the violation: {strict:?}");
        };
        assert_eq!(
            (v.participant, v.tick, v.payload.clone(), v.code),
            ([0; 32], 11, vec![ILLEGAL], ViolationCode(1))
        );
        let live = replay_epoch(&rules, &session, &[0; 3], 10, 4, &batches, true).unwrap();
        assert_eq!(
            live.violations,
            vec![
                v.clone(),
                InputViolation {
                    tick: 12,
                    ..v.clone()
                },
                InputViolation {
                    tick: 13,
                    ..v.clone()
                }
            ]
        );
        // The neutral replacement adds nothing for the offender: only the first tick counted.
        assert_eq!(live.state, vec![1, 4, 4]);
        // With no neutral substitute the event is dropped; the offender's state is the same.
        let dropped = Totals {
            slots: 2,
            neutral: false,
        };
        let live = replay_epoch(&dropped, &session, &[0; 3], 10, 4, &batches, true).unwrap();
        assert_eq!(live.state, vec![1, 4, 4]);
    }

    #[test]
    fn execution_failures_are_never_violations() {
        let session = session(2);
        let (a, b) = (held(0, &[(1, BROKEN)]), held(1, &[]));
        let rules = Totals {
            slots: 2,
            neutral: true,
        };
        for sanitize in [false, true] {
            let out = replay_epoch(
                &rules,
                &session,
                &[0; 3],
                10,
                4,
                &[Some(&a), Some(&b)],
                sanitize,
            );
            assert_eq!(out, Err(ReplayError::Execution("boom".into())));
        }
    }

    #[test]
    fn malformed_inputs_are_refused() {
        let session = session(2);
        let (a, b) = (held(0, &[]), held(1, &[]));
        let rules = Totals {
            slots: 2,
            neutral: true,
        };
        // Wrong slot, wrong range, wrong match, wrong arity and oversize state.
        assert_eq!(
            replay_epoch(
                &rules,
                &session,
                &[0; 3],
                10,
                4,
                &[Some(&b), Some(&a)],
                false
            ),
            Err(ReplayError::Malformed)
        );
        assert_eq!(
            replay_epoch(
                &rules,
                &session,
                &[0; 3],
                9,
                4,
                &[Some(&a), Some(&b)],
                false
            ),
            Err(ReplayError::Malformed)
        );
        let mut foreign = held(0, &[]);
        foreign.match_id = [6; 32];
        assert_eq!(
            replay_epoch(
                &rules,
                &session,
                &[0; 3],
                10,
                4,
                &[Some(&foreign), Some(&b)],
                false
            ),
            Err(ReplayError::Malformed)
        );
        assert_eq!(
            replay_epoch(&rules, &session, &[0; 3], 10, 4, &[Some(&a)], false),
            Err(ReplayError::Malformed)
        );
        assert_eq!(
            replay_epoch(
                &rules,
                &session,
                &[0; MAX_STATE_BYTES + 1],
                10,
                4,
                &[Some(&a), Some(&b)],
                false
            ),
            Err(ReplayError::StateTooLarge)
        );
    }

    #[test]
    fn rotating_order_changes_who_applies_first() {
        // Each apply records the slot order in state; ordering is a session property.
        struct Trail;
        impl StateMachine for Trail {
            fn ruleset_hash(&self) -> Digest {
                [2; 32]
            }
            fn genesis(&self, _: &Session) -> Vec<u8> {
                vec![]
            }
            fn apply(&self, state: &[u8], input: &[u8]) -> Result<Vec<u8>, RuleError> {
                let mut next = state.to_vec();
                next.push(input[0]);
                Ok(next)
            }
        }
        let mut session = session(3);
        let inputs: Vec<Vec<&[u8]>> = vec![vec![&[1u8][..]]; 3];
        let mut v = Vec::new();
        let plain = step_tick(&Trail, &session, vec![], 1, &inputs, false, &mut v).unwrap();
        assert_eq!(plain, vec![0, 1, 2]);
        session.ordering = gv_core::Ordering::Rotating;
        let rotated = step_tick(&Trail, &session, vec![], 1, &inputs, false, &mut v).unwrap();
        assert_eq!(rotated, vec![1, 2, 0]);
    }
}
