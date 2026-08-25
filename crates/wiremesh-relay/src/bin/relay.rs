// relay <bind_udp> [certdir] — QUIC datagram forwarder with mandatory mutual
// TLS. Every accepted connection MUST present a client certificate chaining
// to certdir/ca.pem (enforced in wiremesh_relay::server_config_with_denylist
// via WebPkiClientVerifier, PLUS a rejection for any serial on the loaded
// denylist); connections that don't fail the handshake and never reach the
// registration/forwarding loop below at all.
//
// `certdir` defaults to `/var/lib/wiremesh` (spec §3 identity/state store
// location): the real relay identity (cert/key/ca) is written there, mode
// 0600, by fabric-CA enrollment (Cycle 4c Task 4) — this binary only READS
// it, never writes it. `<certdir>/denylist.json` is loaded fail-static at
// startup (Cycle 4c Task 3): present or not, the relay always starts and
// serves — a missing file just means "nothing revoked yet".
use anyhow::Result;
use clap::Parser;
use quinn::Endpoint;
use std::net::SocketAddr;
use std::path::PathBuf;
use std::time::Duration;

#[derive(Parser)]
// `version` makes clap emit `-V`/`--version` (the crate version) and `about`
// gives `--help` a one-line description — the live-deployment diagnostics
// feature (plan `docs/superpowers/plans/2026-07-28-cli-help-version.md`).
// Without `version` clap rejects `--version` as an unexpected argument.
#[command(
    version,
    about = "WireMesh relay: mTLS QUIC-datagram bridge for NAT-traversal fallback"
)]
struct Args {
    /// UDP address to bind the QUIC endpoint on, e.g. 127.0.0.1:4443.
    bind: SocketAddr,
    /// Directory containing ca.pem + relay.pem/key (from mkcerts, or written
    /// by fabric-CA enrollment in production — see module doc comment).
    #[arg(default_value = "/var/lib/wiremesh")]
    certdir: PathBuf,
    /// Controller Sync dial target (mTLS) as host:port — a DNS hostname
    /// (DDNS controllers) or an IPv4 literal, e.g. ctrl.example.com:9500 or
    /// 127.0.0.1:7000; IPv6 and malformed IPv4-shaped literals are rejected
    /// at boot (v1 is IPv4-only — see `validated_host_port`). When given,
    /// the relay runs a background Sync client (`wiremesh_relay::run_sync`)
    /// that folds the controller's `revoked_serials` into the live denylist
    /// and persists it to `<certdir>/denylist.json`. Resolution happens
    /// inside every `run_sync` call, so the retry loop below re-resolves DNS
    /// on each reconnect. When absent (as in the offline denylist test), the
    /// relay serves using only whatever denylist was already on disk at
    /// startup — no controller involved at all.
    #[arg(long, value_parser = validated_host_port)]
    controller: Option<String>,
}

/// clap value parser for `--controller`: the shared boot-time syntax check
/// (`wiremesh_relay::validate_host_port`, the same one behind the gateway's
/// `--controller-sync`/`--observe`). No DNS — a currently-unresolvable
/// hostname must still boot (fail-static; resolution is per-dial inside
/// `run_sync`) — but an IPv6 literal or a typo'd IPv4-shaped literal like
/// `10.0.0.300:9500` can never dial successfully, so it exits non-zero HERE
/// instead of the sync task logging resolution failures forever, exactly as
/// the old `SocketAddr`-typed flag (and the gateway) behaved.
fn validated_host_port(s: &str) -> Result<String, String> {
    wiremesh_relay::validate_host_port(s)
        .map(|()| s.to_string())
        .map_err(|e| format!("{e:#}"))
}

#[tokio::main]
async fn main() -> Result<()> {
    let args = Args::parse();

    let denylist_path = args.certdir.join("denylist.json");
    let denylist = wiremesh_relay::Denylist::load(&denylist_path)?;
    eprintln!(
        "relay: loaded denylist ({} revoked serial(s)) from {}",
        denylist.snapshot().len(),
        denylist_path.display()
    );

    if let Some(sync_addr) = args.controller {
        let denylist = denylist.clone();
        let certdir = args.certdir.clone();
        let persist_path = denylist_path.clone();
        tokio::spawn(async move {
            // Simple reconnect-with-backoff loop: a controller outage must
            // never take the relay's datagram-forwarding path down with it
            // (fail-static — see module doc comment). Each disconnect just
            // means the relay keeps enforcing whatever denylist it last
            // persisted until the controller comes back. run_sync resolves
            // the host:port target inside every call, so each retry here
            // also re-resolves DNS — a rotated DDNS A record heals without
            // a relay restart.
            loop {
                let result = wiremesh_relay::run_sync(
                    &sync_addr,
                    &certdir,
                    "relay",
                    denylist.clone(),
                    persist_path.clone(),
                )
                .await;
                if let Err(e) = result {
                    eprintln!("relay: sync client error (will retry): {e:#}");
                }
                tokio::time::sleep(Duration::from_secs(5)).await;
            }
        });
    }

    let server_config = wiremesh_relay::server_config_with_denylist(&args.certdir, denylist)?;
    let endpoint = Endpoint::server(server_config, args.bind)?;
    eprintln!("relay: listening on {}", args.bind);

    // The accept -> handshake -> register -> datagram-forward loop itself is
    // graduated into the lib (Cycle 4c Task 7) as `wiremesh_relay::serve`, so
    // it can also be driven in-process (e.g. the gateway's loopback relay
    // tests) without spawning this binary.
    wiremesh_relay::serve(endpoint).await;
    Ok(())
}
