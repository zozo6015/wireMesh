// mkcerts <dir> [gw-id...] — test-support cert generator: a self-signed CA
// plus leaf certs for the relay and every given gateway id (defaulting to
// "gw-A"/"gw-B" if none are given), all signed by that CA. Leaf CN == the id
// used later as the QUIC-level gateway identifier. Production relay/gateway
// certs come from fabric-CA enrollment (Cycle 4c Task 4), not this binary.
//
// Every generated leaf (relay + each gw id) gets an EXPLICIT 16-byte serial
// (rather than rcgen's own random default) and a `<id>.serial` sidecar file
// containing that serial as lowercase hex — the same encoding
// `wiremesh-trust::hex_encode` uses for issued certs — so a test can put a
// leaf's exact serial on a `wiremesh_relay::Denylist` and expect it to match
// what `wiremesh_relay::server_config_with_denylist`'s verifier extracts
// from the live connection's client cert (Cycle 4c Task 3).
//
// The actual cert-generation logic lives in `wiremesh_relay::test_certs`
// (Cycle 4c Task 7 — graduated so it can be called in-process by, e.g., the
// gateway's loopback relay tests without shelling out to this binary); this
// bin is just the CLI wrapper that supplies the default gw-A/gw-B ids.
use anyhow::Result;
use clap::Parser;

#[derive(Parser)]
struct Args {
    /// Directory to write ca.pem, relay.pem/key(+.serial), <gw-id>.pem/key(+.serial) into.
    dir: std::path::PathBuf,
    /// Gateway identities to generate leaf certs for. Defaults to "gw-A"/"gw-B"
    /// (the identities `tests/bridge.rs` expects) when none are given.
    gw_ids: Vec<String>,
}

fn main() -> Result<()> {
    let args = Args::parse();

    let gw_ids: Vec<String> = if args.gw_ids.is_empty() {
        vec!["gw-A".to_string(), "gw-B".to_string()]
    } else {
        args.gw_ids.clone()
    };
    let gw_id_refs: Vec<&str> = gw_ids.iter().map(String::as_str).collect();

    wiremesh_relay::test_certs(&args.dir, &gw_id_refs)?;

    eprintln!(
        "mkcerts: wrote ca + relay + {} into {}",
        gw_ids.join(" + "),
        args.dir.display()
    );
    Ok(())
}
