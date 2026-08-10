//! In-process WireGuard UAPI writer (spec §3, G-1: no `wg` dependency). Renders
//! and applies a full device config to boringtun's unix socket, exactly as
//! `wg syncconf` does: `replace_peers=true` + the complete peer list in one
//! atomic `set` message.
use anyhow::{anyhow, Context};
use std::collections::HashMap;
use std::io::{Read, Write};
use std::net::SocketAddr;
use std::os::unix::net::UnixStream;
use std::time::{Duration, SystemTime};

/// Steady-state WireGuard `persistent_keepalive_interval`, emitted on EVERY
/// peer the gateway configures (mesh-convergence fix T1,
/// `docs/superpowers/plans/2026-07-28-mesh-convergence-fixes.md`).
///
/// Rationale (`docs/research/ops-finding-multi-gateway-convergence.md` §5):
/// the first real 3-segment deployment ran with NO persistent keepalive, so a
/// NAT-ed peer's UDP mapping expired whenever a tunnel idled — the working
/// px↔home path died ~20 minutes after forming and then sawtoothed (works
/// after handshake → NAT forgets → 45s silence → Degraded → punch storm →
/// occasionally re-forms). 25s is the standard WireGuard answer to NAT
/// mapping expiry; it also keeps punch-created mappings warm. Always-on for
/// v1 (tiny overhead, no config knob per the plan) — the steady-state
/// `reconcile` builders emit this unconditionally so no call site can
/// configure a peer without it. The rotation-scoped builders keep an explicit
/// parameter (`main.rs`'s `ROTATION_KEEPALIVE = 3` on transient overlap
/// devices is a documented design choice, and 3s ≤ 25s keeps mappings at
/// least as warm).
pub const PERSISTENT_KEEPALIVE_SECS: u16 = 25;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PeerConfig {
    pub public_key_b64: String,
    pub endpoint: Option<String>,
    pub allowed_ips: Vec<String>,
    pub keepalive_secs: u16,
}

#[derive(Debug, Clone)]
pub struct DeviceConfig {
    pub private_key_b64: String,
    pub listen_port: u16,
    pub peers: Vec<PeerConfig>,
}

/// Decode a 32-byte WireGuard key from base64 to the lowercase-hex the UAPI
/// wire expects.
fn key_b64_to_hex(b64: &str) -> anyhow::Result<String> {
    let raw = base64_decode(b64).with_context(|| "decoding WG key from base64")?;
    if raw.len() != 32 {
        return Err(anyhow!("WG key must be 32 bytes, got {}", raw.len()));
    }
    Ok(raw.iter().map(|b| format!("{b:02x}")).collect())
}

/// Decode a base64 WireGuard public key into the lowercase-hex form the WG
/// UAPI keys its per-peer state by ([`get_peer_liveness`]), so a
/// controller-provided `active_pubkey_b64` can be correlated with the
/// device's live handshake/rx_bytes state. Returns `None` for malformed
/// input or a key that isn't exactly 32 bytes.
///
/// Lives here (rather than in `main.rs`, where it used to) because
/// `rotation::role_b_decisions` — library code — has to answer "is this
/// peer's advertised pending key usable at all?" as a pure decision, and the
/// binary's copy is invisible to the library. Same decode as
/// [`key_b64_to_hex`], `Option`-shaped for callers that treat a bad key as a
/// skip rather than an error.
pub fn pubkey_b64_to_hex(b64: &str) -> Option<String> {
    let raw = base64_decode(b64).ok()?;
    if raw.len() != 32 {
        return None;
    }
    Some(raw.iter().map(|b| format!("{b:02x}")).collect())
}

/// Validate an `ip:port` endpoint as IPv4 before it reaches the UAPI wire.
/// v1 is IPv4-only end to end (spec §1 — the controller binds an `Ipv4Addr`;
/// matches `config.rs`'s IPv6-reject-at-boot policy), so a bracketed
/// (`[…]:port`) or otherwise non-IPv4 endpoint is a hard error rather than a
/// silently-written line boringtun would choke on later.
fn validate_ipv4_endpoint(ep: &str) -> anyhow::Result<()> {
    match ep.parse::<std::net::SocketAddr>() {
        Ok(std::net::SocketAddr::V4(_)) => Ok(()),
        Ok(std::net::SocketAddr::V6(_)) => {
            Err(anyhow!("IPv6 endpoint {ep:?} is unsupported (v1 is IPv4-only)"))
        }
        Err(e) => Err(anyhow!("invalid endpoint {ep:?}: {e}")),
    }
}

/// Can `ep` be written to the UAPI as an `endpoint=` line at all?
///
/// (Backlog item 1) The predicate form of [`validate_ipv4_endpoint`], exposed
/// so the candidate ingest filters in [`crate::state`] are the SAME predicate
/// rather than a second opinion about what is dialable. That matters because
/// the two cannot safely disagree in one direction: a filter LOOSER than this
/// function is a live crash-loop path. `validate_ipv4_endpoint`'s `Err`
/// propagates through [`push_peer_block`] to [`encode_set`], which
/// `apply_state` calls with `?` BEFORE its incremental `match delta`, so the
/// error unwinds out of `run()` past both loops and ends the process from
/// `main`'s `rt.block_on(run(cfg))`.
///
/// Deliberately delegates rather than re-parsing: one definition, one place
/// to change it.
pub fn is_dialable_endpoint(ep: &str) -> bool {
    validate_ipv4_endpoint(ep).is_ok()
}

/// Validate an allowed-ips entry as an IPv4 CIDR (`a.b.c.d/len`) before it
/// reaches the UAPI wire — same IPv4-only rationale as
/// [`validate_ipv4_endpoint`]. An IPv6 CIDR (or malformed entry) is a hard
/// error.
fn validate_ipv4_cidr(cidr: &str) -> anyhow::Result<()> {
    let (ip, len) =
        cidr.split_once('/').ok_or_else(|| anyhow!("allowed_ip {cidr:?} is not CIDR (a.b.c.d/len)"))?;
    let addr = ip
        .parse::<std::net::Ipv4Addr>()
        .map_err(|_| anyhow!("allowed_ip {cidr:?} is not an IPv4 CIDR (v1 is IPv4-only)"))?;
    let prefix: u8 = len.parse().map_err(|_| anyhow!("allowed_ip {cidr:?} has a non-numeric prefix"))?;
    if prefix > 32 {
        return Err(anyhow!("allowed_ip {cidr:?} prefix /{prefix} exceeds /32"));
    }
    let _ = addr;
    Ok(())
}

/// Can `cidr` be written to the UAPI as an `allowed_ip=` line at all?
///
/// (Backlog item 24) The predicate form of [`validate_ipv4_cidr`], exposed so
/// the `allowed_ips` ingest filters in [`crate::state`] are the SAME
/// predicate rather than a second opinion about it — same rationale as
/// [`is_dialable_endpoint`]: a filter LOOSER than this function is a live
/// crash-loop path, and one STRICTER silently strands a correctly-configured
/// route.
pub fn is_valid_ipv4_cidr(cidr: &str) -> bool {
    validate_ipv4_cidr(cidr).is_ok()
}

/// Render one peer's `set` block (public_key + endpoint? + replace_allowed_ips
/// + allowed_ip* + persistent_keepalive_interval). Shared by [`encode_set`]
/// (full config) and [`encode_add_peers`] (incremental add-only). Fallible:
/// the endpoint and every allowed-ips CIDR are validated as IPv4 before ANY
/// field is written (v1 is IPv4-only — see [`validate_ipv4_endpoint`] /
/// [`validate_ipv4_cidr`]), so a non-IPv4/invalid peer fails the whole encode
/// rather than emitting a partial, boringtun-rejected block.
fn push_peer_block(s: &mut String, p: &PeerConfig) -> anyhow::Result<()> {
    // Validate first, mutate second: a bad CIDR must not leave a half-written
    // peer block in `s`.
    if let Some(ep) = &p.endpoint {
        validate_ipv4_endpoint(ep)?;
    }
    for cidr in &p.allowed_ips {
        validate_ipv4_cidr(cidr)?;
    }
    s.push_str(&format!("public_key={}\n", key_b64_to_hex(&p.public_key_b64)?));
    if let Some(ep) = &p.endpoint {
        s.push_str(&format!("endpoint={ep}\n"));
    }
    s.push_str("replace_allowed_ips=true\n");
    for cidr in &p.allowed_ips {
        s.push_str(&format!("allowed_ip={cidr}\n"));
    }
    s.push_str(&format!("persistent_keepalive_interval={}\n", p.keepalive_secs));
    Ok(())
}

pub fn encode_set(cfg: &DeviceConfig) -> anyhow::Result<String> {
    let mut s = String::new();
    s.push_str(&format!("private_key={}\n", key_b64_to_hex(&cfg.private_key_b64)?));
    s.push_str(&format!("listen_port={}\n", cfg.listen_port));
    s.push_str("replace_peers=true\n");
    for p in &cfg.peers {
        push_peer_block(&mut s, p)?;
    }
    s.push('\n'); // blank line terminates the request
    Ok(s)
}

/// Encode an INCREMENTAL ADD-ONLY `set`: only the given peers' blocks, with
/// NO `private_key`/`listen_port`/`replace_peers` lines. Applied to a device
/// that already has those set, this CREATES each peer and leaves every
/// existing peer's live noise session UNTOUCHED — the make-before-break
/// peer-add path (mesh-convergence fix cycle, T8 done-bar; finding §2 in
/// `docs/research/ops-finding-multi-gateway-convergence.md`: a newcomer
/// enrolling must not interrupt an established pair's traffic).
///
/// Safety rests on a boringtun 0.6.0 UAPI fact confirmed from source
/// (`device/api.rs` top-level `set` loop + `device/mod.rs::update_peer`):
/// absent a `replace_peers=true` line, a `public_key=` block dispatches to
/// `api_set_peer`, and `update_peer` for a pubkey NOT already present takes
/// the CREATE path (`Tunn::new`) — the same code initial peer creation runs.
/// The panic ("Modifying existing peers is not yet supported") fires ONLY
/// for an already-present peer, so callers MUST pass only brand-new pubkeys
/// (the `apply_state` delta guarantees this). Every peer still carries the
/// T1 persistent keepalive via [`push_peer_block`].
pub fn encode_add_peers(peers: &[PeerConfig]) -> anyhow::Result<String> {
    let mut s = String::new();
    for p in peers {
        push_peer_block(&mut s, p)?;
    }
    s.push('\n'); // blank line terminates the request
    Ok(s)
}

/// Apply an incremental add-only set (see [`encode_add_peers`]) to `ifname`.
/// The caller MUST have verified every peer is brand-new (not already on the
/// device) — see that function's safety note.
pub fn add_peers(ifname: &str, peers: &[PeerConfig]) -> anyhow::Result<()> {
    send_set(ifname, &encode_add_peers(peers)?)
}

/// Encode OP 1 of the scoped single-peer re-point: REMOVE only the target
/// peer. One `set=1` body with NO `replace_peers`/`private_key`/`listen_port`
/// header, so every OTHER peer's live boringtun `Tunn` session and keepalive
/// timer stay intact; `remove=true` on an absent peer is a no-op (standard
/// UAPI). See [`set_one_peer`] for why this is a SEPARATE message from the
/// re-add.
pub fn encode_remove_peer(public_key_b64: &str) -> anyhow::Result<String> {
    let hex = key_b64_to_hex(public_key_b64)?;
    // Trailing blank line terminates the request.
    Ok(format!("public_key={hex}\nremove=true\n\n"))
}

/// Apply a SCOPED single-peer re-point to `ifname` as TWO separate `set=1`
/// operations — remove, then clean add — leaving every other peer's live
/// session untouched. This is the make-before-break endpoint re-point that
/// replaces the full [`apply`] (`replace_peers=true` = `clear_peers()`, which
/// rebuilt EVERY peer's session — so a punch/relay re-point against one peer
/// reset every OTHER established peer, the session-continuity contention this
/// cycle eliminates).
///
/// TWO messages, NOT one: boringtun 0.6.0's `set` handler does NOT re-create a
/// peer from a re-add block that FOLLOWS a `remove=true` of the SAME key in the
/// SAME `set=1` — the remove wins and the peer VANISHES (observed as `wg show`
/// listing no peers + `endpoint=None`). So:
///
///  1. [`encode_remove_peer`] removes the existing peer (the only way to change
///     it — boringtun's `update_peer` panics on an in-place modify of a present
///     peer, see [`apply`]/[`encode_add_peers`]).
///  2. [`encode_add_peers`] cleanly ADDs the now-absent peer with the new
///     endpoint/allowed-ips/keepalive, via the same `Tunn::new` CREATE path a
///     brand-new peer takes — no in-place modify, no panic.
///
/// Neither op carries `replace_peers`, so no other peer is touched. The
/// re-created peer starts with NO noise session, so the CALLER MUST nudge
/// boringtun to initiate a fresh handshake promptly (spike finding 1); without
/// that nudge the re-added peer flows data but never reports a current
/// handshake — the breakage the earlier scoped attempt hit before the nudge.
pub fn set_one_peer(ifname: &str, peer: &PeerConfig) -> anyhow::Result<()> {
    // Op 1: remove the existing peer (no replace_peers → others untouched).
    send_set(ifname, &encode_remove_peer(&peer.public_key_b64)?)?;
    // Op 2: clean add of the now-absent peer with its new endpoint.
    //
    // PARTIAL-FAILURE SAFETY (MAJOR-2): the remove already succeeded, so if the
    // ADD send fails the peer is now REMOVED from the device. Silently
    // returning would let the caller's change-guard record the re-point as
    // applied while the peer is actually GONE (traffic to it black-holes until
    // some later full apply). So retry the add ONCE, and if it STILL fails
    // propagate the error (never swallow) — the scoped caller then leaves its
    // change-guard un-updated, so the next `apply_state` reconciles and re-adds
    // the peer.
    let add_body = encode_add_peers(std::slice::from_ref(peer))?;
    if let Err(first) = send_set(ifname, &add_body) {
        eprintln!(
            "wiremesh-gateway: scoped peer re-add failed after remove succeeded ({first}); \
             retrying the add once (peer is currently REMOVED)"
        );
        send_set(ifname, &add_body).with_context(|| {
            format!("re-adding peer after remove (peer left REMOVED; first attempt: {first})")
        })?;
    }
    Ok(())
}

/// Derive the base64 WireGuard public key from a base64 private key.
pub fn base64_pub_from_priv(priv_b64: &str) -> anyhow::Result<String> {
    let raw = base64_decode(priv_b64)?;
    let arr: [u8; 32] = raw.as_slice().try_into()
        .map_err(|_| anyhow!("private key must be 32 bytes"))?;
    let secret = boringtun::x25519::StaticSecret::from(arr);
    let public = boringtun::x25519::PublicKey::from(&secret);
    Ok(base64_encode(public.as_bytes()))
}

/// Apply a full device config in one atomic `set` (`replace_peers=true` +
/// the complete peer list).
///
/// CAVEAT (mesh-convergence fix cycle, learned empirically): with this
/// project's boringtun (0.6.0) a full apply is SESSION-DESTRUCTIVE for
/// every peer — `replace_peers=true` is implemented as `clear_peers()`
/// (`device/api.rs`), so all noise sessions and handshake state are
/// rebuilt. The `apply_device_if_changed` change-guard in `main.rs` exists
/// precisely so byte-identical re-applies never reach this function. A
/// surgical single-peer alternative was prototyped (remove+re-add of just
/// the re-pointed peer — the only mutation boringtun supports, since its
/// `update_peer` panics on in-place modification of an existing peer) and
/// REJECTED on evidence: exercising boringtun's live `remove_peer`+re-add
/// path left the re-added peer with traffic flowing but NO current session
/// reported (relay_matrix case1's real-handshake assertion failed
/// deterministically), while the full apply passes.
///
/// The PURE-ADDITION case — a newcomer enrolling while established pairs
/// keep flowing (finding §2 make-before-break, T8 done-bar) — is now handled
/// WITHOUT this destructive path: `apply_state` diffs the applied peer set
/// and, when the only change is added peers, uses the incremental
/// [`add_peers`] set instead, which creates the new peers and leaves every
/// existing session untouched. This full apply remains for the boot/first
/// apply (needs `private_key`/`listen_port`) and for any change that
/// REMOVES or MODIFIES an existing peer (e.g. `set_peer_endpoint`'s endpoint
/// re-point — a modify, where the session reset is acceptable because the
/// re-point already expects a fresh handshake). For those, the finding-§2
/// consequence (an established peer's session reset) is bounded by the
/// change-guard plus the T4 live-endpoint pins, which guarantee the rebuilt
/// peers keep their live endpoints and re-handshake to the RIGHT place
/// immediately.
pub fn apply(ifname: &str, cfg: &DeviceConfig) -> anyhow::Result<()> {
    send_set(ifname, &encode_set(cfg)?)
}

/// Move a LIVE device's WireGuard listen port, in place, with **nothing else**
/// in the `set=1` body — no `private_key`, no `replace_peers`, no peer blocks.
///
/// This is the renormalization primitive of the port-authority fix, piece 2
/// (`docs/research/port-authority-verification-the-shape-was-wrong.md`): after
/// a Role-A cutover the surviving active Device sits on a rotation OFFSET port
/// forever (OD-1), so every durable thing that addresses this gateway — the
/// controller-observed candidate, reported locals, punch candidates — is
/// pointing at a port the active key has permanently left. Once the old epoch
/// is retired the base port is free again, and this puts the survivor back on
/// it.
///
/// # Why this is safe on a live device (boringtun 0.6.0, read from source)
///
///  - `api_set`'s device-section loop maps `listen_port` to
///    `Device::open_listen_socket(port)` and nothing else; a body that carries
///    only this line never reaches `set_key` or `clear_peers`
///    (`device/api.rs`).
///  - `open_listen_socket` closes `udp4`/`udp6`, calls `shutdown_endpoint()`
///    on every peer, then rebinds. It does **not** touch any peer's `Tunn`, so
///    unlike `private_key=` (which rebuilds every session) and
///    `replace_peers=true` (`clear_peers()`) **the noise sessions survive**
///    (`device/mod.rs`).
///  - `Peer::shutdown_endpoint` only `take`s the CONNECTED socket
///    (`endpoint.conn`); `endpoint.addr` is left intact (`device/peer.rs`), so
///    every peer keeps the address it was sending to and simply falls back to
///    `send_to` on the fresh `udp4`.
///  - Both sockets rebind with `set_reuse_address(true)`, and the gateway's
///    only other socket on this port — the transient observe probe — sets
///    `SO_REUSEADDR` too (`observe::reuseport_udp`). Linux's UDP bind conflict
///    check is skipped when BOTH sockets carry `SO_REUSEADDR`, so an in-flight
///    observe probe cannot make this fail with `EADDRINUSE`. (The steady state
///    after this call is byte-for-byte the boot-time arrangement: boringtun on
///    the base port plus the periodic observe probe beside it.)
///
/// The peer-visible consequence is a **source-port change**, not a session
/// reset: our datagrams now leave from `port`, and each peer's boringtun roams
/// its endpoint for us on the first one it authenticates. The caller is
/// expected to prompt that rather than wait for the 25s keepalive.
///
/// # Failure posture: an `Err` here leaves the device HALF-OPEN, not merely no-op
///
/// `open_listen_socket` is **not** atomic. It drops `udp4` **and** `udp6` and
/// calls `shutdown_endpoint()` on every peer BEFORE attempting either bind, and
/// assigns `self.udp4`/`self.udp6` only at the very end (boringtun 0.6.0,
/// `device/mod.rs`). Any error in between — `Socket::new(Domain::IPV6, ..)` on
/// a host with IPv6 disabled, an `EADDRINUSE` from a v4 or v6 conflict,
/// `ENFILE` — surfaces here while leaving the Device with
/// `udp4 = None, udp6 = None`.
///
/// What that actually means is NOT "no sockets at all", and the difference is
/// load-bearing. `register_udp_handler` registers the event against a
/// `try_clone()` — a `dup()`, so a second fd on the SAME kernel socket — and
/// `open_listen_socket` clears by the ORIGINAL's fd. Since `events[]` is indexed
/// by fd, that clear is a no-op: the clone stays in the epoll set, still bound
/// to the OLD port, its handler closure still owning the socket. Observed
/// directly with `ss -lunpe` in a netns (see
/// `docs/research/socket-leak-on-rebind.md`).
///
/// So after a failed rebind the Device keeps RECEIVING on the old port through
/// the leaked clone, while `self.udp4 = None` leaves it unable to SEND. Peers
/// see a gateway that acknowledges nothing. Recovery is a process restart —
/// there is no in-process retry — and the state is arguably nastier than a
/// clean death because it is not silent in the direction an operator watches.
///
/// `TunnelSet::set_listen_port` correctly declines to update its recorded port
/// on an error, but that record then describes a port the Device is not
/// sending from.
///
/// The specific `EADDRINUSE`-against-the-observe-probe case IS ruled out, by
/// the `SO_REUSEADDR` reasoning above; it is every OTHER error that leaves this
/// state.
///
/// > **This paragraph has now been wrong twice.** It first claimed a failed
/// > rebind "leaves the gateway exactly where it was — on the offset port". It
/// > was then corrected to "deaf and mute on every port, receiving nothing".
/// > Both were reasoned from boringtun's source without observing a running
/// > device. The text above is the first version written from `ss` output.
pub fn set_listen_port(ifname: &str, port: u16) -> anyhow::Result<()> {
    // Trailing blank line terminates the request (see `send_set`).
    send_set(ifname, &format!("listen_port={port}\n\n"))
        .with_context(|| format!("moving {ifname} to listen port {port}"))
}

/// Shared UAPI `set=1` round-trip: connect, send `body`, check `errno`.
fn send_set(ifname: &str, body: &str) -> anyhow::Result<()> {
    let path = format!("/var/run/wireguard/{ifname}.sock");
    let mut stream = UnixStream::connect(&path)
        .with_context(|| format!("connecting to WG UAPI socket {path}"))?;
    let req = format!("set=1\n{body}");
    stream.write_all(req.as_bytes()).context("writing UAPI set request")?;
    let mut resp = String::new();
    stream.read_to_string(&mut resp).context("reading UAPI response")?;
    // Response is `errno=<n>\n\n`.
    let errno = resp
        .lines()
        .find_map(|l| l.strip_prefix("errno="))
        .ok_or_else(|| anyhow!("UAPI response missing errno: {resp:?}"))?;
    if errno != "0" {
        return Err(anyhow!("UAPI set failed: errno={errno}"));
    }
    Ok(())
}

// --- UAPI `get=1` read side (Task 9: path-state driver's handshake feed) ---

/// One peer's parsed state from a `get=1` UAPI response — currently only
/// the fields the path-state driver needs (spec §6.1: "authenticated
/// inbound ≈ latest-handshake advancing OR rx bytes increasing").
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub(crate) struct PeerGetInfo {
    pub last_handshake_sec: u64,
    pub last_handshake_nsec: u64,
    pub rx_bytes: u64,
    /// Parsed for per-peer observability (mesh-convergence fix T5,
    /// `docs/research/ops-finding-multi-gateway-convergence.md` §6: every
    /// diagnosis in the incident required UAPI spelunking via debug
    /// containers because the gateway exposed no per-peer rx/tx/handshake
    /// metrics). Same `get=1` response the liveness fields come from.
    pub tx_bytes: u64,
    /// The endpoint the DEVICE is actually using for this peer, as boringtun
    /// reports it — the ground truth the port-authority fix reads through
    /// (`docs/research/port-authority-verification-the-shape-was-wrong.md`,
    /// piece 1). This is NOT necessarily the endpoint we configured:
    /// boringtun's `register_udp_handler` calls `peer.set_endpoint(addr)` on
    /// every SUCCESSFULLY DECAPSULATED datagram, so the value ROAMS to
    /// wherever authenticated traffic is genuinely arriving from (roaming
    /// requires successful decryption, so an off-path sender cannot move it),
    /// and `api_get` emits it from `p.endpoint().addr`.
    ///
    /// `None` when the line is absent (boringtun omits it for a peer with no
    /// endpoint at all) or when it does not parse as a `SocketAddr` — a value
    /// that cannot be parsed must never become a durable pin, so it is
    /// dropped rather than guessed at. Typed as `SocketAddr` rather than
    /// `String` both for that validation and because `SocketAddr: Copy` keeps
    /// this struct — and the public [`PeerLiveness`] it feeds — `Copy`.
    pub endpoint: Option<SocketAddr>,
}

/// Parse a `get=1` UAPI response body into `{pubkey_hex -> PeerGetInfo}`.
/// Pure string parsing, no socket I/O, so it's unit-testable against a
/// fixture without a real WG device.
///
/// Wire format (a `public_key=<hex>` line starts each peer block; fields up
/// to the next `public_key=` line or end-of-response belong to that peer):
/// ```text
/// private_key=<hex>
/// listen_port=<n>
/// public_key=<hex>
/// last_handshake_time_sec=<n>
/// last_handshake_time_nsec=<n>
/// rx_bytes=<n>
/// ...
/// errno=0
///
/// ```
pub(crate) fn parse_get_response(resp: &str) -> HashMap<String, PeerGetInfo> {
    let mut out = HashMap::new();
    let mut current: Option<(String, PeerGetInfo)> = None;
    for line in resp.lines() {
        if let Some(hex) = line.strip_prefix("public_key=") {
            if let Some((key, info)) = current.take() {
                out.insert(key, info);
            }
            current = Some((hex.to_string(), PeerGetInfo::default()));
            continue;
        }
        let Some((_, info)) = current.as_mut() else {
            continue; // fields before the first public_key= (device-level) don't belong to any peer
        };
        if let Some(v) = line.strip_prefix("last_handshake_time_sec=") {
            info.last_handshake_sec = v.parse().unwrap_or(0);
        } else if let Some(v) = line.strip_prefix("last_handshake_time_nsec=") {
            info.last_handshake_nsec = v.parse().unwrap_or(0);
        } else if let Some(v) = line.strip_prefix("rx_bytes=") {
            info.rx_bytes = v.parse().unwrap_or(0);
        } else if let Some(v) = line.strip_prefix("tx_bytes=") {
            info.tx_bytes = v.parse().unwrap_or(0);
        } else if let Some(v) = line.strip_prefix("endpoint=") {
            // Unparseable => `None` (see the field doc): the caller pins this
            // value durably, and a garbled endpoint pin is strictly worse than
            // no pin at all (no pin means "chase the advertised candidate").
            // An IPv6 endpoint is garbled by that same definition — v1 is
            // IPv4-only, so a v6 pin is one this gateway can never apply:
            // `reconcile::device_config_pinned` renders the pin straight back
            // into a UAPI config and `push_peer_block`'s
            // `validate_ipv4_endpoint` refuses it. Dropping it here keeps that
            // rejection at the boundary where it costs a single skipped pin,
            // instead of persisting a pin whose only future is an apply-time
            // failure.
            info.endpoint = v.trim().parse().ok().filter(SocketAddr::is_ipv4);
        }
    }
    if let Some((key, info)) = current.take() {
        out.insert(key, info);
    }
    out
}

/// Reduce parsed `get=1` peer info to `{pubkey_hex -> SystemTime}` for
/// peers that HAVE handshaked at least once. A never-handshaked peer (both
/// `last_handshake_time_{sec,nsec}` are 0, the UAPI's zero-value default)
/// is simply absent from the map, rather than mapping to the Unix epoch —
/// which would be indistinguishable from a genuine handshake at time 0.
///
/// SEMANTICS CAVEAT (mesh-convergence fix cycle root-cause): the WG UAPI
/// spec defines these fields as the ABSOLUTE unix time of the last
/// handshake, but this project's boringtun (0.6.0) fills them with
/// `time_since_last_handshake()` — the ELAPSED duration since the handshake
/// (`device/api.rs`). The `SystemTime` produced here is therefore
/// `UNIX_EPOCH + <elapsed>` under boringtun (a 1970-adjacent value that
/// GROWS between handshakes and DROPS to ~epoch on each new one) and a real
/// wall-clock instant under a spec-conforming implementation. This function
/// deliberately stays a mechanical conversion of what the wire said;
/// consumers that need real event detection or ages must normalize — see
/// `main.rs::reported_handshake_age`. (This is also the true mechanism
/// behind the cycle-4b "handshake time advances every tick with rx flat"
/// quirk: elapsed time simply grows with the wall clock.)
pub(crate) fn handshake_times_from(peers: &HashMap<String, PeerGetInfo>) -> HashMap<String, SystemTime> {
    peers
        .iter()
        .filter(|(_, info)| info.last_handshake_sec != 0 || info.last_handshake_nsec != 0)
        .map(|(k, info)| {
            let t = SystemTime::UNIX_EPOCH
                + Duration::from_secs(info.last_handshake_sec)
                + Duration::from_nanos(info.last_handshake_nsec);
            (k.clone(), t)
        })
        .collect()
}

/// Read the WireGuard device's per-peer latest-handshake times via UAPI
/// `get=1` — the read side of [`apply`]'s writer. Returns `{pubkey_hex ->
/// SystemTime}`; see [`handshake_times_from`] for why never-handshaked
/// peers are absent rather than epoch-valued.
pub fn get_latest_handshakes(ifname: &str) -> anyhow::Result<HashMap<String, SystemTime>> {
    let peers = read_get_response(ifname)?;
    Ok(handshake_times_from(&peers))
}

/// One peer's liveness + traffic snapshot from a single `get=1` round-trip —
/// the feed the path-state driver (and, via it, the per-peer metrics of
/// mesh-convergence fix T5) consumes. `latest_handshake` is `None` for a
/// never-handshaked peer, per [`handshake_times_from`]'s epoch-ambiguity
/// rationale; `rx_bytes`/`tx_bytes` are always present (0 for a peer with no
/// traffic yet).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct PeerLiveness {
    pub latest_handshake: Option<SystemTime>,
    pub rx_bytes: u64,
    pub tx_bytes: u64,
    /// The endpoint the device is ACTUALLY using for this peer right now —
    /// see [`PeerGetInfo::endpoint`] for why this is roamed ground truth
    /// rather than a read-back of what we configured. Carried on the same
    /// snapshot as the liveness counters deliberately: the path tick's
    /// endpoint read-through must only trust an endpoint for a peer it has
    /// just judged LIVE from the very same fetch (see `run_path_ticks`'s
    /// endpoint read-through), so the two must not come from two round-trips
    /// that can disagree.
    pub endpoint: Option<SocketAddr>,
}

/// Reduce parsed `get=1` peer info to `{pubkey_hex -> PeerLiveness}`.
///
/// `rx_bytes` is the original point of this reducer (review finding, Cycle
/// 4b Task 10): the path-state driver's ~1s tick only ever called
/// `on_handshake`, but WG handshakes advance only ~every 120s (rekey) while
/// keepalives bump `rx_bytes` without touching the handshake time. Watching
/// `rx_bytes` for an increase since the previous tick gives the driver a
/// keepalive-visible liveness signal (`Path::on_authenticated_inbound`), so
/// a healthy `Direct` path no longer oscillates to `Degraded` every ~45s.
/// See `docs/research/cycle4b-path-liveness-note.md`. `tx_bytes` rides along
/// for the T5 per-peer observability gauges (finding §6) so the metrics are
/// sourced from the exact same UAPI fetch the path SM diffs — one snapshot,
/// no second socket dance.
pub(crate) fn peer_liveness_from(
    peers: &HashMap<String, PeerGetInfo>,
) -> HashMap<String, PeerLiveness> {
    let times = handshake_times_from(peers);
    peers
        .iter()
        .map(|(k, info)| {
            (
                k.clone(),
                PeerLiveness {
                    latest_handshake: times.get(k).copied(),
                    rx_bytes: info.rx_bytes,
                    tx_bytes: info.tx_bytes,
                    endpoint: info.endpoint,
                },
            )
        })
        .collect()
}

/// Read the WireGuard device's per-peer latest-handshake time AND
/// `rx_bytes`/`tx_bytes` via UAPI `get=1` in a single round-trip — the
/// liveness feed the path-state driver uses (see [`peer_liveness_from`]).
/// Returns `{pubkey_hex -> PeerLiveness}`.
pub fn get_peer_liveness(ifname: &str) -> anyhow::Result<HashMap<String, PeerLiveness>> {
    let peers = read_get_response(ifname)?;
    Ok(peer_liveness_from(&peers))
}

/// Shared UAPI `get=1` round-trip: connect, request, read the full response,
/// and parse it. Both [`get_latest_handshakes`] and [`get_peer_liveness`]
/// build on this so there's exactly one socket dance to get right.
fn read_get_response(ifname: &str) -> anyhow::Result<HashMap<String, PeerGetInfo>> {
    let path = format!("/var/run/wireguard/{ifname}.sock");
    let mut stream = UnixStream::connect(&path)
        .with_context(|| format!("connecting to WG UAPI socket {path}"))?;
    stream.write_all(b"get=1\n\n").context("writing UAPI get request")?;
    let mut resp = String::new();
    stream.read_to_string(&mut resp).context("reading UAPI get response")?;
    Ok(parse_get_response(&resp))
}

// --- minimal base64 (avoid a new workspace dep for two 32-byte keys) ---
const B64: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

pub(crate) fn base64_encode(input: &[u8]) -> String {
    let mut out = String::new();
    for chunk in input.chunks(3) {
        let b = [chunk[0], *chunk.get(1).unwrap_or(&0), *chunk.get(2).unwrap_or(&0)];
        let n = ((b[0] as u32) << 16) | ((b[1] as u32) << 8) | b[2] as u32;
        out.push(B64[((n >> 18) & 63) as usize] as char);
        out.push(B64[((n >> 12) & 63) as usize] as char);
        out.push(if chunk.len() > 1 { B64[((n >> 6) & 63) as usize] as char } else { '=' });
        out.push(if chunk.len() > 2 { B64[(n & 63) as usize] as char } else { '=' });
    }
    out
}

pub(crate) fn base64_decode(s: &str) -> anyhow::Result<Vec<u8>> {
    fn val(c: u8) -> anyhow::Result<u32> {
        match c {
            b'A'..=b'Z' => Ok((c - b'A') as u32),
            b'a'..=b'z' => Ok((c - b'a' + 26) as u32),
            b'0'..=b'9' => Ok((c - b'0' + 52) as u32),
            b'+' => Ok(62),
            b'/' => Ok(63),
            _ => Err(anyhow!("invalid base64 char")),
        }
    }
    let bytes: Vec<u8> = s.bytes().filter(|&c| c != b'=' && !c.is_ascii_whitespace()).collect();
    let mut out = Vec::new();
    for chunk in bytes.chunks(4) {
        let mut n = 0u32;
        for (i, &c) in chunk.iter().enumerate() {
            n |= val(c)? << (18 - 6 * i);
        }
        out.push((n >> 16) as u8);
        if chunk.len() > 2 { out.push((n >> 8) as u8); }
        if chunk.len() > 3 { out.push(n as u8); }
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn b64(bytes: &[u8; 32]) -> String {
        // base64 of a fixed key for a stable expectation
        base64_encode(bytes)
    }

    #[test]
    fn encode_set_renders_device_then_peer_blocks() {
        let priv_raw = [0x11u8; 32];
        let pub_raw = [0x22u8; 32];
        let cfg = DeviceConfig {
            private_key_b64: b64(&priv_raw),
            listen_port: 51820,
            peers: vec![PeerConfig {
                public_key_b64: b64(&pub_raw),
                endpoint: Some("203.0.113.5:51820".into()),
                allowed_ips: vec!["10.10.2.0/24".into()],
                keepalive_secs: 15,
            }],
        };
        let out = encode_set(&cfg).unwrap();
        let priv_hex = "11".repeat(32);
        let pub_hex = "22".repeat(32);
        let expected = format!(
            "private_key={priv_hex}\n\
             listen_port=51820\n\
             replace_peers=true\n\
             public_key={pub_hex}\n\
             endpoint=203.0.113.5:51820\n\
             replace_allowed_ips=true\n\
             allowed_ip=10.10.2.0/24\n\
             persistent_keepalive_interval=15\n\
             \n"
        );
        assert_eq!(out, expected);
    }

    /// The scoped single-peer re-point MUST be TWO separate `set=1` ops —
    /// remove, then a clean add — NEITHER carrying `replace_peers` (or the
    /// device header). Regression pin: the earlier one-message
    /// `remove=true`+re-add of the SAME key made boringtun 0.6 drop the peer
    /// entirely (`wg show`: no peers, `endpoint=None`), so this pins that the
    /// two ops are encoded distinctly and the remove/add live in different
    /// messages. (DeviceHandle-level GET verification — target present with its
    /// new endpoint AND a second pre-existing peer still present — is the
    /// test-author's `tests/scoped_peer_apply.rs`.)
    #[test]
    fn scoped_set_one_peer_is_two_ops_remove_then_add_no_replace_peers() {
        let pub_raw = [0x22u8; 32];
        let peer = PeerConfig {
            public_key_b64: b64(&pub_raw),
            endpoint: Some("203.0.113.5:51820".into()),
            allowed_ips: vec!["10.10.2.0/24".into()],
            keepalive_secs: 25,
        };
        let pub_hex = "22".repeat(32);

        // Op 1: remove ONLY the target peer — no re-add in this message, no
        // replace_peers/private_key/listen_port (every other peer untouched).
        let remove = encode_remove_peer(&peer.public_key_b64).unwrap();
        assert_eq!(remove, format!("public_key={pub_hex}\nremove=true\n\n"));

        // Op 2: a clean ADD of the now-absent peer with its new endpoint — the
        // exact incremental-add encoder (a CREATE, not an in-place modify, so
        // no boringtun `update_peer` panic).
        let add = encode_add_peers(std::slice::from_ref(&peer)).unwrap();
        let expected_add = format!(
            "public_key={pub_hex}\n\
             endpoint=203.0.113.5:51820\n\
             replace_allowed_ips=true\n\
             allowed_ip=10.10.2.0/24\n\
             persistent_keepalive_interval=25\n\
             \n"
        );
        assert_eq!(add, expected_add);

        // The invariant the single-message bug violated: NEITHER op carries
        // `replace_peers` (which would `clear_peers()` every OTHER session) nor
        // the device header — remove and add are SEPARATE `set=1` messages.
        for op in [&remove, &add] {
            assert!(!op.contains("replace_peers"), "scoped op must not replace_peers: {op:?}");
            assert!(!op.contains("private_key="), "scoped op must not carry device header: {op:?}");
            assert!(!op.contains("listen_port="), "scoped op must not carry device header: {op:?}");
        }
        // Op 1 removes; op 2 must NOT (it re-adds the peer).
        assert!(remove.contains("remove=true"), "op 1 removes: {remove:?}");
        assert!(!add.contains("remove=true"), "op 2 must not remove: {add:?}");
    }

    #[test]
    fn peer_without_endpoint_omits_endpoint_line() {
        let cfg = DeviceConfig {
            private_key_b64: base64_encode(&[0u8; 32]),
            listen_port: 1,
            peers: vec![PeerConfig {
                public_key_b64: base64_encode(&[1u8; 32]),
                endpoint: None,
                allowed_ips: vec!["10.0.0.0/8".into()],
                keepalive_secs: 15,
            }],
        };
        let out = encode_set(&cfg).unwrap();
        assert!(!out.contains("endpoint="), "no endpoint line when None:\n{out}");
    }

    /// A realistic two-peer `get=1` response: one peer with a recorded
    /// handshake + rx traffic, one that has never handshaked (all-zero
    /// handshake/traffic fields) — the fixture the brief asked for.
    const GET_RESPONSE_FIXTURE: &str = "\
private_key=1111111111111111111111111111111111111111111111111111111111111111\n\
listen_port=51820\n\
public_key=aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\n\
endpoint=203.0.113.5:51820\n\
last_handshake_time_sec=1700000000\n\
last_handshake_time_nsec=500000000\n\
rx_bytes=12345\n\
tx_bytes=6789\n\
persistent_keepalive_interval=15\n\
allowed_ip=10.10.2.5/32\n\
public_key=bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb\n\
last_handshake_time_sec=0\n\
last_handshake_time_nsec=0\n\
rx_bytes=0\n\
tx_bytes=0\n\
persistent_keepalive_interval=15\n\
allowed_ip=10.10.2.6/32\n\
errno=0\n\
\n";

    #[test]
    fn parse_get_response_extracts_both_peers() {
        let parsed = parse_get_response(GET_RESPONSE_FIXTURE);
        assert_eq!(parsed.len(), 2, "both peers parsed: {parsed:?}");

        let a = parsed
            .get("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa")
            .expect("peer a present");
        assert_eq!(a.last_handshake_sec, 1700000000);
        assert_eq!(a.last_handshake_nsec, 500000000);
        assert_eq!(a.rx_bytes, 12345);
        // T5 pin (mesh-convergence fix cycle): `tx_bytes` is extracted from
        // the same `get=1` block. The fixture deliberately carries DISTINCT
        // rx/tx values (12345 vs 6789) so a swapped- or shared-prefix parse
        // bug (tx landing in rx or vice versa) cannot pass.
        assert_eq!(a.tx_bytes, 6789, "peer a's tx_bytes extracted, distinct from rx");

        let b = parsed
            .get("bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb")
            .expect("peer b present");
        assert_eq!(b.last_handshake_sec, 0);
        assert_eq!(b.last_handshake_nsec, 0);
        assert_eq!(b.rx_bytes, 0);
        assert_eq!(b.tx_bytes, 0, "zero-traffic peer's tx_bytes parsed as 0, not left unset");
    }

    #[test]
    fn handshake_times_from_omits_never_handshaked_peer() {
        let parsed = parse_get_response(GET_RESPONSE_FIXTURE);
        let times = handshake_times_from(&parsed);

        assert_eq!(times.len(), 1, "only the handshaked peer should appear: {times:?}");
        let a_time = times
            .get("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa")
            .expect("handshaked peer present");
        assert_eq!(
            *a_time,
            SystemTime::UNIX_EPOCH + Duration::from_secs(1700000000) + Duration::from_nanos(500000000)
        );
        assert!(
            !times.contains_key("bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"),
            "never-handshaked peer must be absent, not epoch-valued: {times:?}"
        );
    }

    #[test]
    fn peer_liveness_from_preserves_traffic_counters_for_both_peers() {
        let parsed = parse_get_response(GET_RESPONSE_FIXTURE);
        let liveness = peer_liveness_from(&parsed);
        assert_eq!(liveness.len(), 2, "both peers present, unlike handshake_times_from: {liveness:?}");

        let a = liveness
            .get("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa")
            .expect("peer a present");
        assert_eq!(
            a.latest_handshake,
            Some(SystemTime::UNIX_EPOCH + Duration::from_secs(1700000000) + Duration::from_nanos(500000000))
        );
        assert_eq!(a.rx_bytes, 12345, "handshaked peer's rx_bytes preserved");
        // T5 pin: `tx_bytes` rides the same reducer into `PeerLiveness` —
        // the single snapshot both the path SM and the per-peer metrics
        // gauges are sourced from (finding §6: one UAPI fetch, no second
        // socket dance).
        assert_eq!(a.tx_bytes, 6789, "handshaked peer's tx_bytes preserved, distinct from rx");

        let b = liveness
            .get("bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb")
            .expect("peer b present even though never handshaked");
        assert_eq!(b.latest_handshake, None, "never-handshaked peer still has no handshake time");
        assert_eq!(b.rx_bytes, 0, "never-handshaked peer's rx_bytes preserved (0)");
        assert_eq!(b.tx_bytes, 0, "never-handshaked peer's tx_bytes preserved (0)");
    }

    /// One-peer `get=1` response carrying an arbitrary `endpoint=` value —
    /// the same wire shape as [`GET_RESPONSE_FIXTURE`], parameterized so the
    /// endpoint-validation cases below all read the identical block and can
    /// only differ in the value under test.
    fn get_response_with_endpoint(ep: &str) -> String {
        format!(
            "private_key=1111111111111111111111111111111111111111111111111111111111111111\n\
             listen_port=51820\n\
             public_key={PEER_A}\n\
             endpoint={ep}\n\
             last_handshake_time_sec=1700000000\n\
             last_handshake_time_nsec=500000000\n\
             rx_bytes=12345\n\
             tx_bytes=6789\n\
             persistent_keepalive_interval=15\n\
             allowed_ip=10.10.2.5/32\n\
             errno=0\n\
             \n"
        )
    }

    const PEER_A: &str = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";

    fn endpoint_of(resp: &str) -> Option<SocketAddr> {
        parse_get_response(resp).get(PEER_A).expect("peer a present").endpoint
    }

    /// POSITIVE CONTROL for the IPv6-rejection pins below: a normal IPv4
    /// endpoint must still parse to `Some(..)` with the exact addr AND port.
    /// Without this, "reject IPv6" could be satisfied by a parser that
    /// returns `None` for everything — which would silently destroy the
    /// port-authority read-through this field exists for.
    #[test]
    fn parse_get_response_keeps_ipv4_endpoint() {
        assert_eq!(
            endpoint_of(&get_response_with_endpoint("192.0.2.10:51820")),
            Some("192.0.2.10:51820".parse::<SocketAddr>().unwrap()),
            "an IPv4 endpoint must survive parsing as a pinnable value"
        );
        // Second, distinct IPv4 value so the assertion cannot pass on a
        // hard-coded constant, and the PORT specifically is carried through.
        assert_eq!(
            endpoint_of(&get_response_with_endpoint("198.51.100.7:1234")),
            Some(SocketAddr::from(([198, 51, 100, 7], 1234))),
            "the observed source port is the whole point of the read-through"
        );
    }

    /// v1 is IPv4-only. An IPv6 `endpoint=` from the device is exactly the
    /// "garbled pin" the field doc says must never be stored: the caller pins
    /// this DURABLY, `reconcile::device_config_pinned` renders it back into a
    /// UAPI config, and `push_peer_block`'s `validate_ipv4_endpoint` then
    /// REJECTS it — so accepting it here defers a boundary rejection into an
    /// apply-time failure of an already-persisted pin. It must be `None`.
    #[test]
    fn parse_get_response_rejects_ipv6_endpoint_as_unpinnable() {
        // Collected rather than asserted per-iteration so a failure reports
        // EVERY still-accepted literal, not just the first one.
        let accepted: Vec<(&str, SocketAddr)> = [
            "[fe80::1]:51820",                                 // link-local
            "[::1]:51820",                                     // loopback, compressed
            "[2001:0db8:0000:0000:0000:0000:0000:0001]:51820", // full-form literal
            "[2001:db8::1]:51820",                             // compressed global
        ]
        .into_iter()
        .filter_map(|ep| endpoint_of(&get_response_with_endpoint(ep)).map(|got| (ep, got)))
        .collect();
        assert!(
            accepted.is_empty(),
            "IPv6 endpoints must not become durable pins (v1 is IPv4-only), but these parsed: {accepted:?}"
        );
    }

    /// Pre-existing behaviour, pinned so a future rewrite of the endpoint
    /// branch cannot regress it: a value that is not a socket address at all
    /// yields `None` rather than a partial/guessed pin.
    #[test]
    fn parse_get_response_drops_garbled_endpoint() {
        for ep in ["not-an-address", "192.0.2.10", "192.0.2.10:", ":51820", "192.0.2.999:51820"] {
            assert_eq!(
                endpoint_of(&get_response_with_endpoint(ep)),
                None,
                "unparseable endpoint {ep:?} must yield no pin"
            );
        }
    }

    /// Rejecting the endpoint must reject ONLY the endpoint — the peer stays
    /// in the map with its liveness/traffic fields intact, so an IPv6-reporting
    /// device does not blind the path state machine.
    #[test]
    fn ipv6_endpoint_peer_keeps_its_other_fields() {
        let resp = get_response_with_endpoint("[fe80::1]:51820");
        let parsed = parse_get_response(&resp);
        let a = parsed.get(PEER_A).expect("peer still parsed despite bad endpoint");
        assert_eq!(a.endpoint, None, "endpoint dropped");
        assert_eq!(a.last_handshake_sec, 1700000000, "handshake sec preserved");
        assert_eq!(a.last_handshake_nsec, 500000000, "handshake nsec preserved");
        assert_eq!(a.rx_bytes, 12345, "rx_bytes preserved");
        assert_eq!(a.tx_bytes, 6789, "tx_bytes preserved");

        // And the same through the reducer the path tick actually consumes.
        let live = peer_liveness_from(&parsed);
        let a = live.get(PEER_A).expect("peer present in liveness snapshot");
        assert_eq!(a.endpoint, None, "no IPv6 endpoint reaches PeerLiveness either");
        assert_eq!(a.rx_bytes, 12345);
        assert_eq!(
            a.latest_handshake,
            Some(SystemTime::UNIX_EPOCH + Duration::from_secs(1700000000) + Duration::from_nanos(500000000))
        );
    }

    #[test]
    fn parse_get_response_ignores_device_level_fields_before_first_peer() {
        // private_key=/listen_port= precede the first public_key= line and
        // must not be misattributed to a peer or panic the parser.
        let resp = "private_key=deadbeef\nlisten_port=51820\nerrno=0\n\n";
        let parsed = parse_get_response(resp);
        assert!(parsed.is_empty(), "no peers in response: {parsed:?}");
    }

    // -----------------------------------------------------------------
    // `validate_ipv4_endpoint` — the WRITE-side endpoint predicate
    // -----------------------------------------------------------------
    //
    // (Backlog item 1) Everything above this line tests the READ side
    // (`parse_get_response`). The write-side validator had no direct test of
    // any kind, which is out of proportion to its blast radius: its `Err`
    // propagates through `push_peer_block` -> `encode_set` ->
    // `apply_state`'s `uapi::encode_set(&dev).context(..)?`, unwinds out of
    // `async fn run(cfg)` past both loops, and terminates the process from
    // `main`'s `rt.block_on(run(cfg))`. It is a validator that can kill the
    // gateway.
    //
    // It is also now a SHARED DEFINITION. The item-1 candidate filters (in
    // the controller's `Sync.Report` ingress and the gateway's
    // `PeerState`/`state.json` ingest) are each defined as "drop anything
    // this function would reject", so a filter that is LOOSER than this
    // predicate is a live crash-loop path and a filter that is STRICTER
    // silently strands a correctly-addressed gateway with no candidates.
    // These tests are the written form of that definition.
    //
    // Tested here, privately, rather than by widening the function's
    // visibility for tests' sake. `tests/uapi_endpoint_validation.rs` keeps
    // the complementary public-surface coverage — that this predicate is
    // actually REACHED from `encode_set`/`encode_add_peers` — which is a
    // different property and worth having as well.
    //
    // Characterization of existing behaviour: green on the tree that
    // introduced them.

    /// Every form that MUST validate. The predicate is exactly "parses as
    /// `std::net::SocketAddr::V4`", deliberately nothing narrower: port 1 and
    /// port 65535 are as legitimate as 51820, and a public address is as
    /// legitimate as an RFC1918 one.
    #[test]
    fn validate_ipv4_endpoint_accepts_every_ipv4_socket_address_form() {
        for ep in [
            "203.0.113.5:51820", // public, canonical WG port
            "10.0.0.1:1",        // lowest usable port
            "192.168.1.7:65535", // highest port
            "172.16.4.4:51821",  // the +1 overlap port `pending_peer_configs` derives
        ] {
            validate_ipv4_endpoint(ep).unwrap_or_else(|e| {
                panic!(
                    "{ep:?} is a valid IPv4 socket address and MUST validate. Narrowing \
                     this predicate (a port allow-range, an RFC1918-only rule) would \
                     silently cost a correctly-addressed gateway its direct path, and \
                     would put the item-1 candidate filters — which are defined against \
                     this function — out of step with it. Got: {e:#}"
                )
            });
        }
    }

    /// Every form that MUST be rejected, each with the reason it is dangerous
    /// rather than merely wrong. Reaching the UAPI with one of these is fatal
    /// to the process, so a candidate filter that admits any of them is a
    /// crash-loop.
    #[test]
    fn validate_ipv4_endpoint_rejects_every_non_ipv4_socket_address_form() {
        let cases: &[(&str, &str)] = &[
            ("", "empty string: sorts before every real address, so it takes candidates[0] outright"),
            (" ", "whitespace only"),
            ("not-an-endpoint", "unstructured garbage: the base case"),
            (
                "abc:123",
                "a DNS name with a port — THE trap: it survives \
                 `reconcile::pending_peer_configs`' `rsplit_once(':')` + `u16::parse` \
                 half-check, the only other shape check on this path, and dies here \
                 where the error is fatal. v1 dial targets are IPv4 literals; nothing \
                 resolves names at this layer",
            ),
            ("controller.example.com:51820", "the plausible-hostname form of the same trap"),
            ("localhost:51820", "the most plausible one of all — still not a literal"),
            ("10.0.0.5", "no port: the UAPI `endpoint=` line requires ip:port"),
            ("10.0.0.5:", "a present but empty port"),
            (":51820", "a port with no address"),
            ("10.0.0.5:65536", "one past the top of u16"),
            ("10.0.0.5:70000", "well past the top of u16"),
            ("10.0.0.5:-1", "a negative port"),
            ("10.0.0.5:0x1", "a hex port — the port is decimal-only"),
            ("10.0.0.5:+1", "a signed port"),
            ("999.1.1.1:51820", "an out-of-range octet: dotted-quad SHAPE is not enough"),
            ("10.0.0.5.6:51820", "five octets"),
            ("10.0.0:51820", "three octets"),
            (
                "010.0.0.5:51820",
                "a leading-zero octet. Rust's `Ipv4Addr` FromStr refuses these precisely \
                 because C's `inet_aton` would read them as OCTAL — `010` = 8, not 10 — \
                 so the same string can name two different hosts depending on who parses \
                 it. Pinned so a toolchain or hand-rolled-parser change cannot quietly \
                 reintroduce that ambiguity",
            ),
            (" 10.0.0.5:51820", "leading whitespace: `SocketAddr`'s FromStr does not trim"),
            ("10.0.0.5:51820 ", "trailing whitespace, same reason"),
            (
                "10.0.0.5:51820\n",
                "a trailing newline. The UAPI wire format is newline-delimited \
                 key=value lines, so this is a line-INJECTION vector into the boringtun \
                 `set` message, not merely a parse failure",
            ),
            (
                "10.0.0.5:51820\nendpoint=1.2.3.4:1",
                "the explicit UAPI line-injection payload: accepting it would let the \
                 string's author append arbitrary UAPI directives",
            ),
            ("10.0.0.5:51820:51820", "two ports"),
            ("10.0.0.5%eth0:51820", "an IPv4 with a zone index"),
            ("::1:51820", "an unbracketed IPv6-shaped string"),
            ("[fe80::1%eth0]:51820", "a link-local IPv6 with a zone index"),
        ];

        // Collected rather than asserted per-iteration so a failure reports
        // EVERY still-accepted form, not just the first — same discipline as
        // `parse_get_response_rejects_ipv6_endpoint_as_unpinnable` above.
        let accepted: Vec<&(&str, &str)> =
            cases.iter().filter(|(ep, _)| validate_ipv4_endpoint(ep).is_ok()).collect();
        assert!(
            accepted.is_empty(),
            "these must be REJECTED but validated: {accepted:#?}\n\
             Reaching the UAPI with any of them is FATAL: the `Err` this function returns \
             propagates through `push_peer_block` -> `encode_set` -> `apply_state` and \
             unwinds out of `run()` to `main`, ending the process — for every peer at \
             once, since the device config is built from all of them together. This list \
             is also the definition the item-1 candidate filters are written against, so \
             anything that becomes acceptable here silently becomes storable there."
        );
    }

    /// IPv6 literals are rejected through a SEPARATE arm with its own message.
    /// Worth pinning as distinct from a parse failure: this is a deliberate
    /// v1 scope decision (spec §1 — IPv4-only end to end, matching
    /// `config.rs`'s IPv6-reject-at-boot), and an operator reading a gateway
    /// that just died needs to tell "we don't support that yet" apart from
    /// "that isn't an address". Only the one word an operator would grep for
    /// is asserted — not the full wording, which is free to change.
    #[test]
    fn validate_ipv4_endpoint_rejects_ipv6_literals_as_out_of_scope_not_as_garbage() {
        for ep in [
            "[::1]:51820",                                     // loopback, compressed
            "[2001:db8::1]:51820",                             // compressed global
            "[2001:0db8:0000:0000:0000:0000:0000:0001]:51820", // full-form literal
            "[fe80::1]:51820",                                 // link-local
            "[::ffff:10.0.0.5]:51820",                         // IPv4-MAPPED IPv6
        ] {
            let err = validate_ipv4_endpoint(ep)
                .expect_err("v1 is IPv4-only end to end, so an IPv6 literal must not validate");
            assert!(
                format!("{err}").contains("IPv6"),
                "{ep:?} must be rejected as an explicit IPv6 SCOPE decision, and say so. \
                 `[::ffff:10.0.0.5]:51820` is the one that makes this load-bearing: it is \
                 an IPv4 address wearing IPv6 syntax, and it must go down the IPv6 arm \
                 rather than being unwrapped into its embedded IPv4 — otherwise the \
                 bracketed form becomes a way to smuggle an address past a filter that \
                 only inspects dotted quads. Got: {err:#}"
            );
        }
    }

    /// **KNOWN GAP, pinned as characterization — NOT an endorsement.**
    ///
    /// `validate_ipv4_endpoint` is a pure PARSE check. It has no reachability
    /// semantics at all, so every address below validates despite being
    /// undialable as a WireGuard peer endpoint.
    ///
    /// This is a real asymmetry, not a hypothetical one: the gateway's own
    /// `netif::is_usable_ipv4` — which produces the `local_endpoints` a
    /// gateway reports in the first place — deliberately filters loopback,
    /// link-local and unspecified addresses. So the honest-gateway path is
    /// STRICTER than the validator that guards the wire. A gateway that is
    /// compromised, modified, or merely version-skewed can report
    /// `127.0.0.1:51820`, `0.0.0.0:0` or `10.0.0.5:0`, and every one of them
    /// passes here — which means the item-1 candidate filters, defined as
    /// "agrees with this function", will store and re-advertise them to every
    /// peer in the fabric.
    ///
    /// Severity is a rung below the crash-loop item 1 exists to fix: these
    /// parse, so they do NOT kill the process. They poison the peer's direct
    /// path silently instead (and `127.0.0.1:51820` written into a peer's
    /// UAPI points that peer at itself).
    ///
    /// **DO NOT "fix" this by tightening THIS function. Loopback is load-
    /// bearing here.** An automated review (CodeRabbit, 2026-08-10) proposed
    /// exactly that — reject port 0 and every non-unicast IPv4 (unspecified,
    /// loopback, link-local, multicast, broadcast) right here. It would break
    /// the relay data path, fatally. `relay::RelayTransport::connect` binds
    /// its local UDP socket on `127.0.0.1:0` (`relay.rs:130`) and the Cycle-4c
    /// endpoint switch points the relayed peer at that `local_addr()` — so a
    /// LOOPBACK peer endpoint is the normal, correct, production shape of a
    /// relayed path. Rejecting it here returns `Err` from `push_peer_block`,
    /// which is FATAL: it unwinds through `encode_set` and `apply_state` out
    /// of `run()` and ends the process. The "hardening" would take down every
    /// gateway that ever fails over to a relay.
    ///
    /// The underlying concern is real but belongs at a different door. What a
    /// compromised gateway can poison is the CANDIDATE set, and a candidate is
    /// dropped harmlessly, so any reachability policy belongs in the item-1
    /// filters (`services::sync::usable_local_candidates`, `state::
    /// partition_dialable`) where the failure mode is "peer loses a candidate"
    /// rather than "fabric exits". That would make the filters STRICTER than
    /// this validator — the safe direction — and `tests/predicate_equality.rs`
    /// would have to assert containment instead of equality. Filed as backlog
    /// item 26; deliberately not taken here.
    ///
    /// If you are tightening it, THIS is the test to update, on purpose.
    #[test]
    fn validate_ipv4_endpoint_is_parse_only_so_undialable_addresses_are_accepted_today() {
        let undialable: &[(&str, &str)] = &[
            ("10.0.0.5:0", "port 0 is not a dialable UDP port"),
            ("0.0.0.0:51820", "the unspecified address names no host"),
            ("0.0.0.0:0", "both at once"),
            ("127.0.0.1:51820", "loopback — on a PEER this points that peer at itself; \
                                 `netif::is_usable_ipv4` refuses to emit it"),
            ("169.254.1.1:51820", "link-local — `netif::is_usable_ipv4` refuses this too"),
            ("255.255.255.255:65535", "the broadcast address"),
            ("224.0.0.1:51820", "multicast is not a unicast peer endpoint"),
        ];

        let rejected: Vec<&(&str, &str)> =
            undialable.iter().filter(|(ep, _)| validate_ipv4_endpoint(ep).is_err()).collect();
        assert!(
            rejected.is_empty(),
            "these are accepted TODAY and this test records that gap; they now reject: \
             {rejected:#?}\n\
             If you tightened `validate_ipv4_endpoint` on purpose, good — update this \
             test and the item-1 candidate filters TOGETHER, because they are defined \
             against this predicate and a filter left looser than the validator is a \
             crash-loop path."
        );
    }
}
