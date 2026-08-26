//! Client-side enrollment: generate a keypair + CSR, redeem an enrollment
//! token against the controller's `Enrollment.Enroll` RPC, and hand back the
//! signed leaf certificate, its private key, the CA bundle, and the
//! controller-assigned `gateway_id` + `observe_key`.
//!
//! This is the production counterpart to `wiremesh-testkit`'s test-only
//! `StubGateway` enroll flow — the piece that was missing (see
//! `docs/research/operator-enrollment-client-gap.md`). The gateway and relay
//! `enroll` subcommands wrap this and persist the result in the exact on-disk
//! layout their boot path loads.
//!
//! Trust bootstrap is by an explicitly-supplied CA bundle (`ca_pem`), matching
//! the proven testkit path. The enrollment RPC is server-TLS only: the client
//! presents no certificate (it does not have one yet — that is the point).
//!
//! This crate also hosts the shared `host:port` dial-target pieces the
//! gateway and relay Sync clients use — boot-time [`validate_host_port`],
//! the bounded resolver ([`resolve_host_port`]/[`prefer_ipv4`]), and the
//! canonical Sync keepalive constants ([`SYNC_KEEPALIVE_INTERVAL`] etc.,
//! also consumed by the controller's Sync listener) — see the section below.

use anyhow::{anyhow, Context};
use std::net::SocketAddr;
use std::time::Duration;
use tonic::transport::{Certificate, Channel, ClientTlsConfig};
use wiremesh_proto::v1::enrollment_client::EnrollmentClient;
use wiremesh_proto::v1::EnrollRequest;

// ---------------------------------------------------------------------------
// Shared Sync dial-target pieces (Sync keepalive mirrors, Backlog 2).
//
// Extracted from `wiremesh-gateway` (`src/sync.rs`'s resolver + constants,
// `src/config.rs`'s boot-time validation) so the relay's Sync client gets
// the exact same DDNS dial semantics the gateway landed (PR #28,
// `docs/research/ops-finding-sync-half-open-stream.md`): a `host:port`
// target validated at boot, resolved fresh at every dial, first-IPv4-wins,
// no cross-family fallback, bounded lookup — and ONE canonical set of
// keepalive figures for every endpoint of a Sync link. The consumers
// re-export these under their original paths
// (`wiremesh_gateway::sync::{resolve_host_port, prefer_ipv4}`,
// `wiremesh_gateway::config::validate_host_port`,
// `wiremesh_relay::{resolve_host_port, prefer_ipv4, validate_host_port}`),
// so the pinned per-crate test contracts are stable regardless of where the
// code lives.

/// Canonical HTTP/2 keepalive-PING cadence for a Sync link — the ONE value
/// every endpoint derives from: the gateway and relay clients
/// (`http2_keep_alive_interval`, with while-idle) and the controller's Sync
/// listener (`http2_keepalive_interval`). Defined once because BOTH ends of
/// the same link must detect a dead path on the same ~25s worst-case
/// horizon (interval + [`SYNC_KEEPALIVE_TIMEOUT`]) — three per-crate copies
/// of "15" could silently drift apart, leaving one side holding a half-open
/// stream long after the other declared it dead. 15s stays comfortably
/// inside common home-router/NAT idle windows (minutes for TCP) without
/// meaningful load on the controller. Per-endpoint rationale (why a silent
/// Watch stream is dangerous at all) lives with each consumer's
/// re-declaration; the live-found failure is
/// `docs/research/ops-finding-sync-half-open-stream.md`.
pub const SYNC_KEEPALIVE_INTERVAL: Duration = Duration::from_secs(15);

/// Canonical bound on an unanswered keepalive PING before the connection is
/// declared dead — shared by both ends for the same no-drift reason as
/// [`SYNC_KEEPALIVE_INTERVAL`]. Deliberately shorter than the interval so
/// at most one keepalive is ever outstanding.
pub const SYNC_KEEPALIVE_TIMEOUT: Duration = Duration::from_secs(10);

/// Canonical bound on the client-side TCP/TLS dial itself (server side has
/// no dial). Without one, a dial toward a stale DDNS address that
/// blackholes (no RST) can hang a reconnect loop far longer than the DNS
/// record's own churn; a bounded dial keeps the resolve-dial-retry cycle
/// turning so the next attempt picks up the fresh A record.
pub const SYNC_CONNECT_TIMEOUT: Duration = Duration::from_secs(10);

/// Syntax-only boot-time validation of a `host:port` dial target: split on
/// the LAST `:`, require a non-empty host part and a valid `u16` port.
/// Deliberately does NO DNS lookup — a hostname that doesn't resolve right
/// now must still parse, because the gateway boots fail-static with the
/// controller (and possibly the resolver) unreachable; actual resolution is
/// deferred to dial time ([`resolve_host_port`]). Applied by the gateway's
/// `--controller-sync`/`--observe` parsing and the relay bin's
/// `--controller` value parser.
///
/// Two deliberate exceptions to "syntax only", both so a misconfigured unit
/// fails at boot instead of at every dial:
/// - An IPv6 dial-target literal — bracketed (`[…]:port`) or a host that
///   parses as an IPv6 [`std::net::IpAddr`] — is rejected outright: v1 is
///   IPv4-only end to end (the controller binds an `Ipv4Addr`), so an IPv6
///   target can never be reached and would otherwise just fail at every
///   dial forever.
/// - An IPv4-shaped host (digits and dots only; an all-numeric TLD is not a
///   legal DNS name, so such a string can never be a resolvable hostname)
///   must make the WHOLE input parse as a [`SocketAddr`]. Without this, a
///   typo'd literal like `10.0.0.300:9500` would be waved through as a
///   "hostname" and the process would run forever logging resolution
///   failures, where the old `SocketAddr`-typed flag exited non-zero at
///   boot. This costs no DNS and doesn't touch the genuine-hostname path.
///
/// Port `0` is also rejected: it is the OS's "assign me an ephemeral port"
/// wildcard for BINDS, never a dialable destination, so like the two cases
/// above it could only ever fail at every dial. (A tightening over the
/// original gateway-local version, which permitted it.)
pub fn validate_host_port(s: &str) -> anyhow::Result<()> {
    let (host, port) = s
        .rsplit_once(':')
        .ok_or_else(|| anyhow!("expected host:port, got {s:?}"))?;
    if host.is_empty() {
        return Err(anyhow!("empty host in {s:?}"));
    }
    let port: u16 = port
        .parse()
        .with_context(|| format!("invalid port in {s:?}"))?;
    if port == 0 {
        return Err(anyhow!("port 0 in {s:?} is not a dialable target"));
    }
    if host.starts_with('[') || matches!(host.parse(), Ok(std::net::IpAddr::V6(_))) {
        return Err(anyhow!(
            "IPv6 dial target {s:?} is unsupported (v1 is IPv4-only)"
        ));
    }
    if host.chars().all(|c| c.is_ascii_digit() || c == '.') {
        s.parse::<SocketAddr>()
            .map(|_| ())
            .with_context(|| format!("invalid IP literal in {s:?}"))?;
    }
    Ok(())
}

/// Bound on the DNS lookup in [`resolve_host_port`]. `getaddrinfo` has no
/// application-level timeout of its own, and a connect timeout cannot cover
/// the resolve phase because resolution happens BEFORE the dial — so without
/// this bound a hung OS resolver (e.g. the DDNS host's configured nameserver
/// blackholing) would stall the caller's reconnect/observe loop
/// indefinitely: the same silent-hang class the Sync keepalive exists to
/// kill (`docs/research/ops-finding-sync-half-open-stream.md`). On expiry
/// the caller gets an error and retries on its own cadence, each attempt
/// resolving fresh.
const RESOLVE_TIMEOUT: Duration = Duration::from_secs(10);

/// Resolve a `host:port` dial target — a DNS hostname or an IPv4 literal —
/// to one `SocketAddr`: the first IPv4 result ([`prefer_ipv4`]). A name that
/// resolves to only IPv6 is an ERROR, not a fallback — v1 is IPv4-only end
/// to end (spec §1; the controller itself binds an `Ipv4Addr`), so an IPv6
/// address can never reach a v1 controller. Callers resolve fresh at every
/// dial/tick ON PURPOSE: a DDNS name's A record changes when the ISP rotates
/// the controller's public IP, and per-reconnect (gateway Sync, relay Sync)
/// / per-tick (gateway observe) re-resolution is what picks the new address
/// up without a process restart
/// (`docs/research/operator-remote-deployment-notes.md` Finding 3). IP
/// literals pass through `lookup_host` without touching DNS, so netns tests
/// and IP-configured deployments never depend on a resolver.
pub async fn resolve_host_port(s: &str) -> anyhow::Result<SocketAddr> {
    let addrs: Vec<SocketAddr> = tokio::time::timeout(RESOLVE_TIMEOUT, tokio::net::lookup_host(s))
        .await
        .map_err(|_| anyhow!("DNS resolution of {s:?} timed out after {RESOLVE_TIMEOUT:?}"))?
        .with_context(|| format!("resolving {s:?}"))?
        .collect();
    prefer_ipv4(&addrs)
        .ok_or_else(|| anyhow!("{s:?} resolved to no IPv4 addresses (v1 is IPv4-only)"))
}

/// The pure address-selection policy behind [`resolve_host_port`]: the first
/// IPv4 result, `None` when the list has none. Deliberately NO cross-family
/// fallback: v1 is IPv4-only end to end (spec §1 — the controller binds an
/// `Ipv4Addr`), so an IPv6 candidate is a dead end and "falling back" to one
/// would only trade a clear resolution error for an unreachable-dial loop.
/// Factored out of the resolver so the selection is checkable against a
/// synthetic candidate list, without a resolver in the loop.
pub fn prefer_ipv4(addrs: &[SocketAddr]) -> Option<SocketAddr> {
    addrs.iter().find(|a| a.is_ipv4()).copied()
}

/// The signed identity material returned by a successful enrollment. The
/// caller is responsible for persisting it (`key_pem` is a private key — it
/// must never be logged and must land on disk mode 0600).
pub struct EnrollOutcome {
    pub cert_pem: String,
    pub key_pem: String,
    pub ca_bundle_pem: String,
    pub gateway_id: u64,
    pub observe_key: String,
}

/// Generate a fresh keypair + CSR (subject CN = `common_name`), dial
/// `Enrollment.Enroll` at `controller_addr` (host:port of the controller TCP
/// port) over server-TLS trusting `ca_pem`, and redeem `token`.
///
/// `wg_pubkey` is the enrolling gateway's WireGuard public key (base64); pass
/// `""` for a relay, which has none. `endpoint` is an optional advertised
/// `ip:port` (`""` when unknown).
///
/// # `client_version` is a PARAMETER, and that is the whole point (B10)
///
/// The caller passes its OWN compile-time crate version (the `env!` of the
/// standard Cargo version key). This crate must never expand that macro
/// itself, and a source guard asserts the macro key appears nowhere under
/// `crates/wiremesh-enroll/src/` — which is why this comment describes it
/// rather than spelling it, so the guard can stay a plain literal grep with
/// no comment-stripping and no risk of matching its own explanation.
///
/// `env!` expands at its DEFINITION site, not its call site. Both the gateway
/// and the relay enroll through this one shared function, so an `env!` here
/// would stamp BOTH with `wiremesh-enroll`'s own version — and
/// `scripts/set-version.sh` stamps only the five shipped crates, which does
/// not include this one, so the value would ship as a permanent `"0.1.0"` on
/// every gateway and every relay. That is worse than reporting nothing: it is
/// a confident wrong answer in the one field whose entire purpose is
/// detecting version skew, and being non-empty it would store as a real value
/// instead of the honest NULL.
///
/// Pass `""` to mean "not reported" — it is stored as NULL, never as `''`.
pub async fn enroll(
    controller_addr: &str,
    ca_pem: &str,
    token: &str,
    cidrs: &[String],
    wg_pubkey: &str,
    endpoint: &str,
    common_name: &str,
    client_version: &str,
) -> anyhow::Result<EnrollOutcome> {
    // Keypair + CSR. Mirrors `wiremesh_testkit::gen_csr` (rcgen 0.13): the
    // private key stays local; only the CSR (public half + CN) goes to the CA.
    let key_pair = rcgen::KeyPair::generate().context("generating enrollment key pair")?;
    let key_pem = key_pair.serialize_pem();
    let mut params =
        rcgen::CertificateParams::new(Vec::<String>::new()).context("building CSR params")?;
    params
        .distinguished_name
        .push(rcgen::DnType::CommonName, common_name);
    let csr_pem = params
        .serialize_request(&key_pair)
        .context("building CSR")?
        .pem()
        .context("PEM-encoding CSR")?;

    // TLS channel trusting the controller's CA. `domain_name` matches the
    // controller leaf's SAN/CN posture (the testkit dials "127.0.0.1").
    let tls = ClientTlsConfig::new()
        .ca_certificate(Certificate::from_pem(ca_pem))
        .domain_name("127.0.0.1");
    let channel = Channel::from_shared(format!("https://{controller_addr}"))
        .context("controller addr must form a valid URI")?
        .tls_config(tls)
        .context("configuring enrollment TLS trust of the controller CA")?
        .connect()
        .await
        .with_context(|| format!("connecting to controller enrollment at {controller_addr}"))?;

    let resp = EnrollmentClient::new(channel)
        .enroll(EnrollRequest {
            token: token.to_string(),
            csr_pem,
            cidrs: cidrs.to_vec(),
            wg_pubkey: wg_pubkey.to_string(),
            endpoint: endpoint.to_string(),
            client_version: client_version.to_string(),
        })
        .await
        .context("Enrollment.Enroll")?
        .into_inner();

    Ok(EnrollOutcome {
        cert_pem: resp.cert_pem,
        key_pem,
        ca_bundle_pem: resp.ca_bundle_pem,
        gateway_id: resp.gateway_id,
        observe_key: resp.observe_key,
    })
}
