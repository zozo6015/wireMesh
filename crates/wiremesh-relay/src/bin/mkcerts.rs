// mkcerts <dir> — test-support cert generator: a self-signed CA plus leaf
// certs for the relay and two gateways ("gw-A", "gw-B"), all signed by that
// CA. Leaf CN == the id used later as the QUIC-level gateway identifier.
// Production relay/gateway certs come from fabric-CA enrollment (Cycle 4c
// Task 4), not this binary.
use anyhow::Result;
use clap::Parser;
use rcgen::{BasicConstraints, CertificateParams, DnType, IsCa, KeyPair};

#[derive(Parser)]
struct Args {
    /// Directory to write ca.pem, relay.pem/key, gw-A.pem/key, gw-B.pem/key into.
    dir: std::path::PathBuf,
}

fn main() -> Result<()> {
    let args = Args::parse();
    std::fs::create_dir_all(&args.dir)?;

    let ca_key = KeyPair::generate()?;
    let mut ca_params = CertificateParams::new(vec![])?;
    ca_params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
    let ca_cert = ca_params.self_signed(&ca_key)?;
    std::fs::write(args.dir.join("ca.pem"), ca_cert.pem())?;

    // SANs include the loopback-adjacent test addresses used by natlab labs
    // (203.0.113.1 / 198.51.100.1, TEST-NET-3/TEST-NET-2) so the same certs
    // work whether a test dials 127.0.0.1 (server_name = the leaf's CN, e.g.
    // "relay") or a future netns-based test dials one of these IPs directly.
    for name in ["relay", "gw-A", "gw-B"] {
        let key = KeyPair::generate()?;
        let mut params = CertificateParams::new(vec![
            name.to_string(),
            "203.0.113.1".to_string(),
            "198.51.100.1".to_string(),
        ])?;
        params.distinguished_name.push(DnType::CommonName, name);
        let cert = params.signed_by(&key, &ca_cert, &ca_key)?;
        std::fs::write(args.dir.join(format!("{name}.pem")), cert.pem())?;
        std::fs::write(args.dir.join(format!("{name}.key")), key.serialize_pem())?;
    }

    eprintln!("mkcerts: wrote ca + relay + gw-A + gw-B into {}", args.dir.display());
    Ok(())
}
