//! Task 15: the controller-side UDP observation endpoint (spec §6.1) — a
//! cycle-2 stand-in for the real WG-socket NAT-observation probe. Cycle 4
//! replaces this whole scheme with a probe carried over the actual
//! WireGuard UDP socket plus the brokered hole-punch choreography; this
//! task is scoped to just the endpoint + candidate-endpoint plumbing.
//!
//! Reuses the UDP-echo pattern from Phase 0's `spike/punch/src/bin/observe.rs`
//! (bind a UDP socket, on the `AOBS` magic echo the observed source
//! `ip:port` back to the sender) but that spike version is deliberately
//! UNAUTHENTICATED — anyone on the internet can hit it and get their own
//! address echoed back. That's fine for a throwaway spike binary, but the
//! controller's endpoint additionally feeds a *stateful* side effect (it
//! records the observed address as a specific gateway's candidate endpoint,
//! surfaced to every peer), so an unauthenticated version here would let
//! any internet scanner plant an arbitrary candidate for any enrolled
//! gateway. This module adds the missing authentication.
//!
//! # Wire format
//!
//! A probe is exactly [`PROBE_LEN`] (44) bytes, no framing beyond UDP's own
//! datagram boundary:
//!
//! ```text
//! byte:   0        4                  12                              44
//!         | "AOBS" | gateway_id (u64 BE) | MAC (32 bytes, see below)     |
//! ```
//!
//! # Authentication (cycle-2 stand-in)
//!
//! Every enrolled gateway is issued a random 32-byte `observe_key` at
//! enrollment (`Db::enroll_gateway`), returned to it exactly once in
//! `EnrollResponse.observe_key`. A probe's MAC is
//! `sha256(observe_key || MAGIC || gateway_id_be)` — a keyed hash, not a
//! textbook HMAC construction. That's a deliberate simplification (the task
//! brief explicitly allows "HMAC ... or a simpler MAC"): a real HMAC needs
//! an `hmac` crate this workspace doesn't otherwise depend on, and the
//! length-extension weakness a naive `H(key || message)` construction
//! normally has doesn't apply here because the message is a single
//! fixed-length, fixed-shape blob the verifier reconstructs itself byte for
//! byte (there's no attacker-extensible tail to exploit). Cycle 4 replaces
//! this entire scheme with the real WG-socket-authenticated probe, so this
//! is not meant to be a long-lived cryptographic primitive.
//!
//! The controller looks up the claimed `gateway_id`'s stored `observe_key`
//! (only if that gateway is currently `active` — see
//! `Db::gateway_observe_key`) and recomputes the same MAC. Any mismatch, or
//! any gateway_id that doesn't resolve to an active gateway, or any
//! datagram that isn't exactly [`PROBE_LEN`] bytes with the right magic, is
//! DROPPED silently: no echo, no candidate recorded. This stops an
//! anonymous scanner from FORGING a probe for a gateway whose `observe_key`
//! it doesn't hold.
//!
//! # What this stand-in does NOT protect against: replay
//!
//! The MAC is over a FIXED input (`observe_key || MAGIC || gateway_id`) with
//! no nonce, no timestamp, and — critically — no binding to the observed
//! source address. So the 44-byte probe for a given gateway is a CONSTANT:
//! anyone who can CAPTURE one valid probe on the wire can REPLAY those exact
//! bytes later, from their own address, WITHOUT ever holding `observe_key`,
//! and the controller will accept it and overwrite that gateway's candidate
//! endpoint with the replayer's observed source. In other words this
//! stand-in authenticates that SOME key-holder once sent a probe for this
//! gateway; it does NOT prove the CURRENT sender holds the key, and it does
//! not freshness- or origin-bind the observation. Anti-replay
//! (nonce/timestamp binding, binding the MAC to the observed source, and
//! binding the whole exchange to the gateway's actual WG socket) arrives
//! with cycle 4's real WG-socket probe, which replaces this endpoint
//! entirely — this is deliberately not fixed here (a challenge/response
//! bolted onto a soon-to-be-deleted stand-in buys nothing).
//!
//! This replayability has no exploit surface in cycle 2: nothing yet
//! CONSUMES `candidate_endpoints` (no data plane, no hole-punch — those are
//! cycle 4), so a redirected candidate changes only a projected field no
//! component acts on. The honest framing matters anyway so cycle 4 doesn't
//! inherit this as an assumed-solved property.
//!
//! On a valid probe, the controller: (1) echoes the observed UDP source
//! `ip:port` (as text, e.g. `"127.0.0.1:54321"`) back to the sender, and
//! (2) records that same address as the gateway's candidate endpoint
//! (`Db::set_candidate_endpoint`), which `crate::routes`/`crate::projection`
//! surface into every OTHER gateway's `Peer.candidate_endpoints`.

use sha2::{Digest, Sha256};
use tokio::net::UdpSocket;
use tokio::sync::{broadcast, oneshot};

use crate::db_async::DbHandle;
use crate::projection::ChangeEvent;

/// The probe's magic prefix — identical to Phase 0's spike (`spike/punch`)
/// so the wire pattern is recognizably the same primitive, just now with an
/// identity + MAC appended.
pub const MAGIC: &[u8; 4] = b"AOBS";

const GATEWAY_ID_LEN: usize = 8;
const MAC_LEN: usize = 32;

/// Total length of a well-formed probe datagram: `MAGIC` + an 8-byte
/// big-endian gateway id + a 32-byte MAC. Anything else is dropped outright
/// (see [`spawn`]'s doc comment).
pub const PROBE_LEN: usize = MAGIC.len() + GATEWAY_ID_LEN + MAC_LEN;

/// Recomputes the MAC a probe for `gateway_id`, authenticated with
/// `observe_key_hex` (the exact string the gateway learned at enrollment),
/// must carry. Shared by the verifying server below and
/// `wiremesh-testkit::StubGateway::probe_observe`, which must build the
/// identical MAC to be accepted — see this module's doc comment for the
/// construction and why it's not a textbook HMAC.
pub fn compute_mac(observe_key_hex: &str, gateway_id: u64) -> [u8; MAC_LEN] {
    let mut hasher = Sha256::new();
    hasher.update(observe_key_hex.as_bytes());
    hasher.update(MAGIC);
    hasher.update(gateway_id.to_be_bytes());
    hasher.finalize().into()
}

/// Builds a full [`PROBE_LEN`]-byte probe datagram for `gateway_id`,
/// authenticated with `observe_key_hex`. The one function a gateway-side
/// caller (`wiremesh-testkit::StubGateway::probe_observe`) needs to produce
/// an accepted probe.
pub fn build_probe(observe_key_hex: &str, gateway_id: u64) -> Vec<u8> {
    let mut buf = Vec::with_capacity(PROBE_LEN);
    buf.extend_from_slice(MAGIC);
    buf.extend_from_slice(&gateway_id.to_be_bytes());
    buf.extend_from_slice(&compute_mac(observe_key_hex, gateway_id));
    buf
}

/// Constant-time-ish equality check for two equal-length MAC byte strings:
/// every byte pair is compared (via XOR-and-OR-accumulate) regardless of
/// where the first difference falls, rather than short-circuiting on the
/// first mismatch — avoids the most obvious timing side-channel a naive
/// `==` would have. Not a hardened `subtle`-crate-grade comparison (this
/// workspace doesn't depend on one), but adequate for a cycle-2 stand-in
/// verifying a locally-computed 32-byte digest.
fn mac_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    let mut diff = 0u8;
    for (x, y) in a.iter().zip(b.iter()) {
        diff |= x ^ y;
    }
    diff == 0
}

/// Spawns the observation endpoint's receive loop on an already-bound
/// `socket`, running until `shutdown` fires (mirrors every other listener
/// `serve()` starts — see `crate::serve`'s doc comment and
/// `RunningController::shutdown`). Returns the task's `JoinHandle` so the
/// caller can fold it into the same bounded-join-then-abort teardown every
/// other server task already gets.
///
/// Every accepted datagram is checked against [`PROBE_LEN`]/`MAGIC`/the
/// claimed gateway's stored `observe_key`; anything that fails ANY check is
/// silently dropped — never echoed, never recorded, and never logged with
/// its raw bytes (which could be attacker-controlled garbage) beyond the
/// (already-public) source address and a short reason.
pub fn spawn(
    socket: UdpSocket,
    db: DbHandle,
    change_tx: broadcast::Sender<ChangeEvent>,
    mut shutdown: oneshot::Receiver<()>,
) -> tokio::task::JoinHandle<()> {
    tokio::spawn(async move {
        // Large enough for any well-formed PROBE_LEN=44-byte probe with
        // generous headroom; anything bigger is oversized/malformed and
        // gets dropped by the length check in `handle_probe` regardless.
        let mut buf = [0u8; 512];
        loop {
            let (n, from) = tokio::select! {
                res = socket.recv_from(&mut buf) => match res {
                    Ok(v) => v,
                    Err(e) => {
                        eprintln!("wiremesh-controller: observe socket recv error: {e}");
                        continue;
                    }
                },
                _ = &mut shutdown => break,
            };

            if let Err(reason) = handle_probe(&buf[..n], from, &socket, &db, &change_tx).await {
                eprintln!(
                    "wiremesh-controller: dropped observation probe from {from}: {reason}"
                );
            }
        }
    })
}

/// Verifies one datagram and, if valid, echoes + records it. Returns `Err`
/// with a short, non-sensitive reason for anything dropped (see [`spawn`]'s
/// doc comment on what never gets logged).
async fn handle_probe(
    datagram: &[u8],
    from: std::net::SocketAddr,
    socket: &UdpSocket,
    db: &DbHandle,
    change_tx: &broadcast::Sender<ChangeEvent>,
) -> Result<(), &'static str> {
    if datagram.len() != PROBE_LEN {
        return Err("wrong length");
    }
    if &datagram[0..4] != MAGIC {
        return Err("bad magic");
    }
    let gateway_id_bytes: [u8; GATEWAY_ID_LEN] = datagram[4..12]
        .try_into()
        .expect("slice is exactly GATEWAY_ID_LEN bytes");
    let gateway_id = u64::from_be_bytes(gateway_id_bytes);
    let claimed_mac = &datagram[12..PROBE_LEN];

    let observe_key = db
        .gateway_observe_key(gateway_id as i64)
        .await
        .map_err(|_| "db error looking up observe_key")?
        .ok_or("unknown or inactive gateway_id")?;

    let expected_mac = compute_mac(&observe_key, gateway_id);
    if !mac_eq(claimed_mac, &expected_mac) {
        return Err("MAC verification failed");
    }

    // Authenticated: echo the observed source address back to the sender,
    // then durably record it as this gateway's candidate endpoint.
    let observed = from.to_string();
    let _ = socket.send_to(observed.as_bytes(), from).await;

    let revision = db
        .set_candidate_endpoint(gateway_id as i64, observed.clone())
        .await
        .map_err(|_| "recording candidate endpoint failed")?;

    // Publish a Delta so an already-open Sync.Watch stream sees the new
    // candidate without waiting for a reconnect (bonus — see
    // `ChangeEvent::EndpointObserved`'s doc comment). Re-reads the
    // gateway's current identity/allowed_ips/keys the same way
    // `EnrollmentSvc`/`AdminSvc::rotate_key` do for their own events.
    if let Ok(Some(identity)) = db.gateway_identity_by_id(gateway_id as i64).await {
        if let (Ok(allowed_ips), Ok(keys)) = (
            db.cidrs_for_segment(identity.segment_id).await,
            db.all_keys_for_gateway(gateway_id as i64).await,
        ) {
            let _ = change_tx.send(ChangeEvent::EndpointObserved {
                gateway_id: gateway_id as i64,
                segment_name: identity.segment_name,
                allowed_ips,
                keys,
                candidate_endpoint: observed,
                revision,
            });
        }
    }

    Ok(())
}
