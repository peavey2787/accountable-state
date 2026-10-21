//! Optional disclosure policy: how an application projects certified state for one observer.
//! A view is a presentation decision of the application, not network access control.
use gv_core::PlayerId;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Visibility {
    Public,
    OwnerOnly,
    AuthorizedTeam,
    HiddenUntilReveal,
    NeverReveal,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ObserverRole {
    Participant,
    Opponent,
    Spectator,
    Arbiter,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AuthorizedView {
    pub bytes: Vec<u8>,
    pub disclosure: Visibility,
}

/// Implemented next to a [`crate::StateMachine`] when observers must not see all of its state.
pub trait ViewPolicy {
    fn view_for(
        &self,
        state: &[u8],
        observer: &PlayerId,
        role: ObserverRole,
    ) -> Result<AuthorizedView, String>;
}
