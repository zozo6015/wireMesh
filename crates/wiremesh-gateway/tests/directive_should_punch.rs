//! FIX B pin — the controller-directive punch precondition (directive-storm
//! fix, gateway side).
//!
//! v0.2.4 stopped tick-driven `ProbeDirect` punch spawns, but the
//! `SyncEvent::Punch` directive arm in `main.rs` still spawns
//! `punch_and_apply` regardless of the peer's path state — the
//! make-before-break guard inside `punch_and_apply` then yields once per
//! directive with the "deferring direct punch" log line, so a
//! controller-side directive storm burst-fires that line forever. The fix:
//! the directive arm only spawns a punch when the punch would actually be
//! accepted by `punch_and_apply`'s guard — i.e. the path map has NO entry
//! for the peer, or the entry is `Connecting` AND `relay_pointed` is false
//! (`punch_and_apply` creates a fresh `Connecting` entry for an unknown
//! peer, then requires `Connecting && !relay_pointed`). Otherwise it skips
//! SILENTLY, mirroring the existing silent back-off skip.
//!
//! TDD: this file is authored AHEAD of the implementation and is EXPECTED
//! to fail to compile until FIX B lands. Target surface — a pure helper in
//! the path module (the natural public home next to `PathState` itself, so
//! both the directive arm in `main.rs` and these tests can reach it):
//!
//! ```ignore
//! // crates/wiremesh-gateway/src/path.rs
//! pub fn directive_should_punch(state: Option<PathState>, relay_pointed: bool) -> bool;
//! ```
//!
//! No sockets, no clocks — same pure-surface approach as `path.rs`'s own
//! state machine and `punch_backoff.rs`.

use wiremesh_gateway::path::{directive_should_punch, PathState};

/// An unknown peer (no path-map entry yet) is exactly the fresh-directive
/// case the punch exists for: spawn.
#[test]
fn no_path_entry_punches() {
    assert!(
        directive_should_punch(None, false),
        "a directive for a peer with no path entry must spawn a punch"
    );
}

/// `Connecting` with the WG endpoint NOT pointed at a relay is the one
/// live-entry state `punch_and_apply`'s guard accepts: spawn.
#[test]
fn connecting_unpointed_punches() {
    assert!(
        directive_should_punch(Some(PathState::Connecting), false),
        "Connecting with relay_pointed=false must spawn a punch"
    );
}

/// `Connecting` while the WG endpoint already points at a relay socket is
/// the transition window `punch_and_apply` defers on — the directive arm
/// must not even spawn (a spawn here is one guaranteed defer-line).
#[test]
fn connecting_pointed_does_not_punch() {
    assert!(
        !directive_should_punch(Some(PathState::Connecting), true),
        "Connecting with relay_pointed=true must not spawn a punch"
    );
}

/// Any settled or non-`Connecting` state must not spawn, REGARDLESS of
/// `relay_pointed` — `punch_and_apply`'s guard would defer every one of
/// these, so spawning is pure defer-line spam:
/// - `Direct`: the pair already converged; nothing to punch.
/// - `Relayed`: make-before-break — a punch trial must never disturb a
///   flowing relay path (cutover is the documented fast-follow).
/// - `Degraded`/`Disconnected`: the path tick driver owns recovery
///   (Retry / backoff-gated StartPunch), not the controller directive.
#[test]
fn non_connecting_states_never_punch() {
    for state in [
        PathState::Direct,
        PathState::Degraded,
        PathState::Relayed,
        PathState::Disconnected,
    ] {
        for relay_pointed in [false, true] {
            assert!(
                !directive_should_punch(Some(state), relay_pointed),
                "{state:?} (relay_pointed={relay_pointed}) must not spawn a punch"
            );
        }
    }
}
