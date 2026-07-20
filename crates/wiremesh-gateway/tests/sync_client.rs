//! Sync client against the real in-process controller (no netns needed).
//! ./dev.sh run "cargo test -p wiremesh-gateway --test sync_client -- --nocapture"
use wiremesh_gateway::identity::Identity;
use wiremesh_gateway::sync;
use wiremesh_gateway::uapi::base64_pub_from_priv;
use wiremesh_testkit::{enroll_one, TestController};

#[tokio::test]
async fn receives_snapshot_and_reports_version() {
    let h = TestController::start().await;
    // Enroll two gateways so peer-of relationships exist.
    //
    // Adapted from the brief: `enroll_one` is a free function taking
    // `&TestController` (not a `TestController` method) and returns a bare
    // `StubGateway` (it already panics internally via `.expect(...)` on any
    // enrollment failure), not a `Result` — see
    // `crates/wiremesh-testkit/src/lib.rs`'s `enroll_one`.
    let g1 = enroll_one(&h, "seg-a", "10.10.1.0/24").await;
    let _g2 = enroll_one(&h, "seg-b", "10.10.2.0/24").await;

    // Build the gateway Identity from the enrolled StubGateway's material.
    //
    // Adapted from the brief:
    //  - `cert_pem()`, `key_pem()`, `ca_bundle_pem()` return `&str`, not
    //    `String`, so they're `.to_string()`'d here.
    //  - the gateway id accessor is `id()`, not `gateway_id()`.
    //  - `StubGateway` has no `observe_key()` accessor at all (the field is
    //    private, used only internally by `probe_observe`); `sync::connect`/
    //    `watch`/`report` never read `Identity::observe_key`, so it's filled
    //    with a placeholder empty string here rather than left unconstructed.
    let id = Identity {
        cert_pem: g1.cert_pem().to_string(),
        key_pem: g1.key_pem().to_string(),
        ca_bundle_pem: g1.ca_bundle_pem().to_string(),
        gateway_id: g1.id(),
        observe_key: String::new(),
        wg_private_key_b64: {
            let pk = String::from_utf8(std::process::Command::new("wg").arg("genkey").output().unwrap().stdout).unwrap().trim().to_string();
            let _ = base64_pub_from_priv(&pk).unwrap();
            pk
        },
    };

    let mut client = sync::connect(h.sync_tcp_addr(), &id).await.expect("mTLS connect");
    let mut stream = sync::watch(&mut client).await.expect("watch");
    let mut cur = None;
    // The first Sync message is always a snapshot, surfaced as SyncEvent::State.
    let ds = match sync::next_event(&mut stream, &mut cur).await.expect("first msg").expect("snapshot") {
        sync::SyncEvent::State(ds) => ds,
        sync::SyncEvent::Punch(p) => panic!("expected snapshot, got punch directive: {p:?}"),
    };
    // Gateway A's peer is gateway B (seg-b, 10.10.2.0/24).
    assert!(ds.peers.iter().any(|p| p.allowed_ips.contains(&"10.10.2.0/24".to_string())),
            "snapshot lists peer B's segment: {:?}", ds.peers);

    sync::report(&mut client, ds.policy_version, vec![]).await.expect("report ack");
    let _ = stream; // keep alive
}
