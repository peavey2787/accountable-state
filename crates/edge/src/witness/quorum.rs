//! Head-register traffic on witness links: a witness answers owners' requests from its durable
//! cell; a player-side node surfaces the witnesses' answers to the host.
use super::{Event, LinkId, Msg, WitnessNode};
use crate::quorum::{CellStore, QuorumMsg, RegisterWitness};
use crate::StateMachine;
use gv_core::{MatchId, ParticipantId};

/// Type-erased [`RegisterWitness`], so the node does not carry the store's type.
pub(super) trait Responder: Send {
    fn respond(&mut self, match_id: MatchId, msg: &QuorumMsg) -> Vec<QuorumMsg>;
}

impl<S: CellStore + Send> Responder for RegisterWitness<S> {
    fn respond(&mut self, match_id: MatchId, msg: &QuorumMsg) -> Vec<QuorumMsg> {
        self.handle(match_id, msg)
    }
}

impl<R: StateMachine + Clone> WitnessNode<R> {
    /// Act as a head-register acceptor. Requests are answered only for the player on the link:
    /// a link cannot recover, fence or store for anyone else.
    pub fn enable_register<S: CellStore + Send + 'static>(&mut self, witness: RegisterWitness<S>) {
        self.register = Some(Box::new(witness));
    }

    /// Send a register message to the witnesses I am linked to (`to` = one of them, or all).
    pub fn send_quorum(&mut self, to: Option<ParticipantId>, msg: &QuorumMsg) {
        let links: Vec<LinkId> = self
            .links
            .iter()
            .filter(|(_, l)| !l.blocked && l.peer.is_some_and(|p| to.is_none_or(|t| t == p)))
            .filter(|(_, l)| l.peer.is_some_and(|p| self.witnesses.contains(&p)))
            .map(|(k, _)| *k)
            .collect();
        for l in links {
            self.send(l, &Msg::Quorum(msg.clone()));
        }
    }

    pub(super) fn on_quorum(&mut self, link: LinkId, msg: QuorumMsg) {
        let Some(peer) = self.links.get(&link).and_then(|l| l.peer) else {
            return;
        };
        match &msg {
            QuorumMsg::Recover(_) | QuorumMsg::Store(_) | QuorumMsg::HeldReq { .. } => {
                self.answer_request(link, peer, &msg)
            }
            _ if self.witnesses.contains(&peer) => self.events.push_back(Event::Quorum {
                link,
                from: peer,
                msg,
            }),
            _ => self.strike(link),
        }
    }

    fn answer_request(&mut self, link: LinkId, peer: ParticipantId, msg: &QuorumMsg) {
        let owned = match msg {
            QuorumMsg::Recover(r) => r.owner == peer,
            QuorumMsg::Store(c) => c.owner() == peer,
            _ => self.roster.contains(&peer), // HeldReq: any member may gather receipts
        };
        if !owned {
            return self.strike(link);
        }
        let match_id = self.match_id;
        let replies = self
            .register
            .as_mut()
            .map(|r| r.respond(match_id, msg))
            .unwrap_or_default();
        for r in replies {
            self.send(link, &Msg::Quorum(r));
        }
    }
}
