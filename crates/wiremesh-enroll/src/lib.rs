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

use anyhow::Context;
use tonic::transport::{Certificate, Channel, ClientTlsConfig};
use wiremesh_proto::v1::enrollment_client::EnrollmentClient;
use wiremesh_proto::v1::EnrollRequest;

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
pub async fn enroll(
    controller_addr: &str,
    ca_pem: &str,
    token: &str,
    cidrs: &[String],
    wg_pubkey: &str,
    endpoint: &str,
    common_name: &str,
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
