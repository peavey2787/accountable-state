//! Crash/fault injection points on the persistence-to-send path.
//!
//! A failpoint is a named place in the code (`hit("commit.after_sync")`). Armed through the
//! `GV_FAILPOINT=name[:nth[:abort|error]]` environment variable (whole process) or [`arm`]
//! (current thread, for tests), the `nth` hit (default 1) either aborts the process, like a
//! kill -9 at that exact instruction, or returns an I/O error. Unarmed, a hit is a no-op.
use std::cell::RefCell;
use std::collections::HashMap;
use std::io;
use std::sync::{Mutex, OnceLock};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Action {
    /// `std::process::abort()`: nothing after this instruction runs.
    Abort,
    /// Return an I/O error to the caller (a disk-full / EIO style failure).
    Error,
}

#[derive(Clone, Debug)]
struct Armed {
    name: String,
    nth: u64,
    action: Action,
}

fn parse(spec: &str) -> Option<Armed> {
    let mut it = spec.split(':');
    let name = it.next().filter(|n| !n.is_empty())?.to_string();
    let nth = it.next().map_or(Some(1), |n| n.parse().ok())?;
    let action = match it.next() {
        None | Some("abort") => Action::Abort,
        Some("error") => Action::Error,
        Some(_) => return None,
    };
    Some(Armed { name, nth, action })
}

fn env_armed() -> &'static Option<Armed> {
    static ENV: OnceLock<Option<Armed>> = OnceLock::new();
    ENV.get_or_init(|| std::env::var("GV_FAILPOINT").ok().and_then(|s| parse(&s)))
}

fn counts() -> &'static Mutex<HashMap<String, u64>> {
    static C: OnceLock<Mutex<HashMap<String, u64>>> = OnceLock::new();
    C.get_or_init(|| Mutex::new(HashMap::new()))
}

thread_local! {
    static LOCAL: RefCell<Option<(Armed, u64)>> = const { RefCell::new(None) };
}

/// Arm one failpoint for the current thread (tests). Replaces any previous one.
pub fn arm(name: &str, nth: u64, action: Action) {
    LOCAL.with(|l| {
        *l.borrow_mut() = Some((
            Armed {
                name: name.into(),
                nth,
                action,
            },
            0,
        ));
    });
}

pub fn disarm() {
    LOCAL.with(|l| *l.borrow_mut() = None);
}

/// Execute a triggered action (abort the process, or return the injected error).
pub fn fire(action: Action, name: &str) -> io::Result<()> {
    match action {
        Action::Abort => std::process::abort(),
        Action::Error => Err(io::Error::other(format!("failpoint {name}"))),
    }
}

/// Mark a failpoint. Returns `Err` when an armed `error` failpoint triggers.
pub fn hit(name: &str) -> io::Result<()> {
    match check(name) {
        Some(action) => fire(action, name),
        None => Ok(()),
    }
}

/// Like [`hit`] but returns the triggered action instead of executing it, so the caller can first
/// leave the on-disk state a real crash would (for example a half-written record).
pub fn check(name: &str) -> Option<Action> {
    let local = LOCAL.with(|l| {
        let mut l = l.borrow_mut();
        match l.as_mut() {
            Some((a, n)) if a.name == name => {
                *n += 1;
                (*n == a.nth).then_some(a.action)
            }
            _ => None,
        }
    });
    if local.is_some() {
        return local;
    }
    if let Some(a) = env_armed() {
        if a.name == name {
            let mut c = counts().lock().unwrap_or_else(|e| e.into_inner());
            let n = c.entry(name.to_string()).or_insert(0);
            *n += 1;
            if *n == a.nth {
                return Some(a.action);
            }
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn spec_parsing_is_strict() {
        assert!(parse("a").is_some());
        assert_eq!(
            parse("a:3:error").map(|a| (a.nth, a.action)),
            Some((3, Action::Error))
        );
        assert!(parse("").is_none());
        assert!(parse("a:x").is_none());
        assert!(parse("a:1:explode").is_none());
    }

    #[test]
    fn nth_hit_errors_once() {
        arm("p", 2, Action::Error);
        assert!(hit("p").is_ok());
        assert!(hit("p").is_err());
        assert!(hit("p").is_ok());
        assert!(hit("other").is_ok());
        disarm();
    }
}
