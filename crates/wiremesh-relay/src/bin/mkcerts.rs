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
use anyhow::Result;
use clap::Parser;
use rcgen::{BasicConstraints, CertificateParams, DnType, IsCa, KeyPair, SerialNumber};

#[derive(Parser)]
struct Args {
    /// Directory to write ca.pem, relay.pem/key(+.serial), <gw-id>.pem/key(+.serial) into.
    dir: std::path::PathBuf,
    /// Gateway identities to generate leaf certs for. Defaults to "gw-A"/"gw-B"
    /// (the identities `tests/bridge.rs` expects) when none are given.
    gw_ids: Vec<String>,
}

/// A fresh, random 16-byte serial — same width as
/// `wiremesh-trust::random_serial`. Not cryptographically tied to that
/// function (this is test tooling, not the real CA), but deliberately the
/// same byte length so serial encoding/normalization behaves identically.
fn random_serial_bytes() -> [u8; 16] {
    use std::time::{SystemTime, UNIX_EPOCH};
    // No `rand` dependency in this crate; a simple splitmix64-style mix
    // seeded from wall-clock time plus PID is more than sufficient entropy
    // for test-only, non-security-sensitive serial uniqueness.
    let seed = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_nanos())
        .unwrap_or(0)
        ^ (std::process::id() as u128) << 64;
    let mut state = seed as u64 ^ 0x9E3779B97F4A7C15;
    let mut bytes = [0u8; 16];
    for chunk in bytes.chunks_mut(8) {
        state ^= state << 13;
        state ^= state >> 7;
        state ^= state << 17;
        chunk.copy_from_slice(&state.to_le_bytes()[..chunk.len()]);
    }
    bytes
}

fn main() -> Result<()> {
    let args = Args::parse();
    std::fs::create_dir_all(&args.dir)?;

    let ca_key = KeyPair::generate()?;
    let mut ca_params = CertificateParams::new(vec![])?;
    ca_params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
    let ca_cert = ca_params.self_signed(&ca_key)?;
    std::fs::write(args.dir.join("ca.pem"), ca_cert.pem())?;

    let gw_ids: Vec<String> = if args.gw_ids.is_empty() {
        vec!["gw-A".to_string(), "gw-B".to_string()]
    } else {
        args.gw_ids.clone()
    };

    // SANs include the loopback-adjacent test addresses used by natlab labs
    // (203.0.113.1 / 198.51.100.1, TEST-NET-3/TEST-NET-2) so the same certs
    // work whether a test dials 127.0.0.1 (server_name = the leaf's CN, e.g.
    // "relay") or a future netns-based test dials one of these IPs directly.
    let mut names: Vec<String> = vec!["relay".to_string()];
    names.extend(gw_ids.iter().cloned());
    for name in &names {
        let key = KeyPair::generate()?;
        let mut params = CertificateParams::new(vec![
            name.to_string(),
            "203.0.113.1".to_string(),
            "198.51.100.1".to_string(),
        ])?;
        params.distinguished_name.push(DnType::CommonName, name.as_str());
        let serial = random_serial_bytes();
        params.serial_number = Some(SerialNumber::from_slice(&serial));
        let cert = params.signed_by(&key, &ca_cert, &ca_key)?;
        std::fs::write(args.dir.join(format!("{name}.pem")), cert.pem())?;
        std::fs::write(args.dir.join(format!("{name}.key")), key.serialize_pem())?;
        let serial_hex: String = serial.iter().map(|b| format!("{b:02x}")).collect();
        std::fs::write(args.dir.join(format!("{name}.serial")), &serial_hex)?;
    }

    eprintln!(
        "mkcerts: wrote ca + relay + {} into {}",
        gw_ids.join(" + "),
        args.dir.display()
    );
    Ok(())
}
