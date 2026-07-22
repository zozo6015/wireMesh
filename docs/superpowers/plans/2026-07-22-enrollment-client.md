# Enrollment Client Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: superpowers:subagent-driven-development — separate test-author / implementer / dedicated-runner / reviewer per task. Steps use checkbox (`- [ ]`) tracking.

**Goal:** Ship a production client that turns an enrollment token into the on-disk identity a `wiremesh-gateway` / `wiremesh-relay` loads at boot — closing the gap recorded in `docs/research/operator-enrollment-client-gap.md` so the K8s operator can bootstrap gateway/relay pods.

**Architecture:** One shared library crate `wiremesh-enroll` performs the token→cert half (generate rcgen keypair + CSR, dial the controller's `Enrollment.Enroll` RPC over server-TLS trusting the controller CA, return the leaf cert / key / CA bundle / gateway_id / observe_key). Two thin `enroll` subcommands consume it: the gateway one also mints a WireGuard x25519 keypair and writes the `Identity` JSON layout; the relay one writes the `ca.pem`/`relay.pem`/`relay.key` PEM layout.

**Tech Stack:** Rust, tonic 0.12 (`tls`, workspace), rcgen 0.13, rand 0.8, boringtun x25519 (gateway only), wiremesh-proto generated `EnrollmentClient`.

## Global Constraints

- All builds/tests run in-container via `./dev.sh run "<cmd>"`, foreground, one at a time. Network/integration tests serial: `-- --test-threads=1 --nocapture`.
- Enrollment contract is fixed by proto (`proto/wiremesh/v1/enrollment.proto`): `EnrollRequest { token, csr_pem, cidrs, wg_pubkey, endpoint }` → `EnrollResponse { cert_pem, ca_bundle_pem, gateway_id, observe_key }`. The `Enrollment.Enroll` RPC is served on the controller's TCP port (`tcp_addr()`), server-TLS, `domain_name("127.0.0.1")` in tests.
- Trust bootstrap: the client trusts the controller by an explicitly-supplied CA bundle PEM (`--ca`), mirroring the proven `wiremesh-testkit` path. (Token-`@sha256:` fingerprint pinning is a future enhancement, out of scope.)
- Gateway on-disk layout is EXACTLY what `crates/wiremesh-gateway/src/identity.rs` `Identity::load` reads: `identity.json` (serde of `Identity { cert_pem, key_pem, ca_bundle_pem, gateway_id, observe_key, wg_private_key_b64 }`) + `wg_private.key`, both mode 0600. REUSE `Identity::store` — do not hand-roll the write.
- Relay on-disk layout is EXACTLY what `crates/wiremesh-relay/src/lib.rs` loads: `ca.pem`, `relay.pem`, `relay.key` in `certdir`, each mode 0600 individually.
- WG key generation must match the repo's existing method (`crates/wiremesh-gateway/src/epochkeys.rs::generate_next`): `OsRng.fill_bytes(&mut [0u8;32])` → `uapi::base64_encode` for the private, `uapi::base64_pub_from_priv` for the public.
- Never log any token or private key. Fix the code, never weaken a test, to get green.

---

### Task 1: `wiremesh-enroll` shared crate — the token→cert core

**Files:**
- Create: `crates/wiremesh-enroll/Cargo.toml`, `crates/wiremesh-enroll/src/lib.rs`
- Create: `crates/wiremesh-enroll/tests/enroll_live.rs`
- Modify: root `Cargo.toml` `[workspace] members` (add `"crates/wiremesh-enroll"`)

**Interfaces — Produces:**
```rust
pub struct EnrollOutcome {
    pub cert_pem: String,
    pub key_pem: String,        // the rcgen leaf private key (PEM) — never leaves here except to the caller
    pub ca_bundle_pem: String,
    pub gateway_id: u64,
    pub observe_key: String,
}
/// Generate a keypair+CSR (CN = `common_name`), dial `Enrollment.Enroll` at
/// `controller_addr` over server-TLS trusting `ca_pem`, redeem `token`.
pub async fn enroll(
    controller_addr: &str,   // host:port of the controller TCP port
    ca_pem: &str,            // controller CA bundle to trust
    token: &str,
    cidrs: &[String],
    wg_pubkey: &str,         // "" for a relay
    endpoint: &str,          // "" for a gateway that hasn't observed its mapping yet
    common_name: &str,       // "gateway" | "relay"
) -> anyhow::Result<EnrollOutcome>;
```

- [ ] **Step 1 (test-author): failing integration test** `tests/enroll_live.rs`:
  `enroll_redeems_token_and_returns_signed_leaf` — spin a `wiremesh_testkit` `TestController`, mint a gateway enrollment token via its admin surface (`MintToken { kind: "gateway", bound_cidrs, rebind_segment_id: 0 }` — discover the exact testkit helper; a segment may need creating first so the bound CIDR resolves), call `wiremesh_enroll::enroll(controller.tcp_addr(), controller.ca_bundle_pem(), &token, &cidrs, &wg_pubkey, "", "gateway")`, and assert: `cert_pem` contains `BEGIN CERTIFICATE`, `ca_bundle_pem` non-empty, `gateway_id > 0`, `observe_key` non-empty. Use a real generated WG pubkey (`uapi` is gateway-internal, so in the test generate any valid 32-byte base64 or reuse a testkit helper). Serial, `--nocapture`.
- [ ] **Step 2: run — RED** (`enroll` undefined / crate absent).
- [ ] **Step 3 (implementer): the crate.** Cargo.toml deps: `tonic` (workspace, tls), `rcgen` (workspace), `anyhow`, `tokio` (workspace), `wiremesh-proto { path = "../wiremesh-proto" }`; dev-dep `wiremesh-testkit { path = "../wiremesh-testkit" }`. `lib.rs`: generate `rcgen::KeyPair` + CSR via `CertificateParams::new([]).push CommonName; serialize_request(&kp)`; `key_pem = kp.serialize_pem()`; build a `Channel` to `https://{controller_addr}` with `ClientTlsConfig::new().ca_certificate(Certificate::from_pem(ca_pem)).domain_name("127.0.0.1")`; `EnrollmentClient::new(channel).enroll(EnrollRequest {…})`; map response → `EnrollOutcome`.
- [ ] **Step 4: GREEN** the integration test.
- [ ] **Step 5: commit** `feat(enroll): wiremesh-enroll shared token→cert client (Task 1)`.

### Task 2: `wiremesh-gateway enroll` subcommand

**Files:**
- Create: `crates/wiremesh-gateway/src/enroll.rs`
- Modify: `crates/wiremesh-gateway/src/main.rs` (subcommand dispatch), `crates/wiremesh-gateway/Cargo.toml` (add `wiremesh-enroll`), `crates/wiremesh-gateway/src/uapi.rs` (make `base64_encode` `pub` if not already — `base64_pub_from_priv` is already `pub`)

**Interfaces — Consumes:** `wiremesh_enroll::enroll`. **Produces:** a CLI path `wiremesh-gateway enroll --token <t> --controller <host:port> --ca <ca.pem-path> --state-dir <dir> [--cidr <c>]… [--endpoint <ep>]` that writes `Identity` via `Identity::store`.

- [ ] **Step 1 (test-author): failing test** `crates/wiremesh-gateway/tests/enroll_cmd.rs`:
  `enroll_writes_loadable_identity` — `TestController` + minted token, call the gateway's enroll entrypoint (expose `pub async fn run_enroll(args…) -> anyhow::Result<()>` in `enroll.rs` so the test drives it without a subprocess), point `--state-dir` at a tempdir, then assert `wiremesh_gateway::identity::Identity::load(dir)` succeeds and its `gateway_id` matches and `wg_private_key_b64` derives (via `uapi::base64_pub_from_priv`) to the pubkey the controller stored. Serial, `--nocapture`.
- [ ] **Step 2: run — RED.**
- [ ] **Step 3 (implementer):** `enroll.rs` — generate WG key (`OsRng.fill_bytes([0u8;32])` → `uapi::base64_encode` priv, `uapi::base64_pub_from_priv` pub); call `wiremesh_enroll::enroll(controller, ca, token, cidrs, &wg_pub, endpoint, "gateway")`; build `Identity { cert_pem: out.cert_pem, key_pem: out.key_pem, ca_bundle_pem: out.ca_bundle_pem, gateway_id: out.gateway_id, observe_key: out.observe_key, wg_private_key_b64: wg_priv }`; `.store(state_dir)`. In `main.rs`, before `GatewayConfig::from_env()`, if `args().nth(1) == Some("enroll")` dispatch to `run_enroll` (parse the `--flags`), else the existing path.
- [ ] **Step 4: GREEN.**
- [ ] **Step 5: commit** `feat(gateway): enroll subcommand writes bootable Identity (Task 2)`.

### Task 3: `wiremesh-relay enroll` subcommand

**Files:**
- Create: `crates/wiremesh-relay/src/bin/enroll.rs` (or a subcommand of `relay.rs`; a dedicated `enroll` bin keeps `relay.rs`'s positional CLI intact)
- Modify: `crates/wiremesh-relay/Cargo.toml` (add `wiremesh-enroll`)

**Interfaces — Consumes:** `wiremesh_enroll::enroll`. **Produces:** `wiremesh-relay-enroll --token <t> --controller <host:port> --ca <ca.pem-path> --certdir <dir> --endpoint <ip:port>` writing `ca.pem`/`relay.pem`/`relay.key` (0600 each).

- [ ] **Step 1 (test-author): failing test** `crates/wiremesh-relay/tests/enroll_cmd.rs`:
  `enroll_writes_relay_identity_0600` — `TestController` + a minted **relay** token (`MintToken { kind: "relay", … }`), drive a `pub async fn run_enroll(…)` in the enroll module pointed at a tempdir `--certdir`, then assert `ca.pem`, `relay.pem`, `relay.key` all exist, each is mode `0600`, and `relay.pem` contains `BEGIN CERTIFICATE`. Serial, `--nocapture`.
- [ ] **Step 2: run — RED.**
- [ ] **Step 3 (implementer):** call `wiremesh_enroll::enroll(controller, ca, token, &[], "", endpoint, "relay")`; write `certdir/ca.pem` = `out.ca_bundle_pem`, `certdir/relay.pem` = `out.cert_pem`, `certdir/relay.key` = `out.key_pem`, each with an explicit `set_permissions(0o600)` after write (mirror `identity.rs::write_0600`).
- [ ] **Step 4: GREEN.**
- [ ] **Step 5: commit** `feat(relay): enroll bin writes ca/relay cert identity (Task 3)`.

---

**After Task 3:** resume the operator plan (`2026-07-22-kubernetes-operator.md`). The Task-4 gateway/relay workload builders now emit a real `enroll` init-container (`command: ["/usr/local/bin/wiremesh-gateway","enroll", …]`) sharing the state-dir/certdir volume with the main container, sourcing the token from the mounted enrollment-token Secret and the CA from the controller-CA Secret.
