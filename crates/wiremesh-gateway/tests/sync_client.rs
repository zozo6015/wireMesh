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

    let mut client = sync::connect(&h.sync_tcp_addr().to_string(), &id).await.expect("mTLS connect");
    let mut stream = sync::watch(&mut client).await.expect("watch");
    let mut cur = None;
    // The first Sync message is always a snapshot, surfaced as SyncEvent::State.
    let ds = match sync::next_event(&mut stream, &mut cur).await.expect("first msg").expect("snapshot") {
        sync::SyncEvent::State(ds) => ds,
        sync::SyncEvent::Punch(p) => panic!("expected snapshot, got punch directive: {p:?}"),
        sync::SyncEvent::Rotate(r) => panic!("expected snapshot, got rotate directive: {r:?}"),
    };
    // Gateway A's peer is gateway B (seg-b, 10.10.2.0/24).
    assert!(ds.peers.iter().any(|p| p.allowed_ips.contains(&"10.10.2.0/24".to_string())),
            "snapshot lists peer B's segment: {:?}", ds.peers);

    sync::report(&mut client, ds.policy_version, vec![], vec![], vec![], None).await.expect("report ack");
    let _ = stream; // keep alive
}

/// (Sync session generation, gateway side) The nonce this process stamps on
/// `Sync.Watch` and every `Sync.Report` must be NONZERO and STABLE, and a
/// real watch-then-report round trip against a real controller must succeed.
///
/// Both properties are load-bearing, and the round trip is what proves them
/// jointly rather than in isolation:
///
///  - NONZERO: 0 is the wire's legacy/unknown sentinel. The controller's
///    reject predicate accepts a 0 on either side, so a gateway that sent 0
///    would silently opt itself out of the whole scheme and its own delayed
///    pre-restart reports would keep being accepted.
///  - STABLE (per PROCESS, not per connection): the rotation tick's unary
///    epoch-ack `Report` dials its OWN short-lived channel, entirely outside
///    the sync loop's Watch. If `session_generation()` minted a fresh value
///    per call, that ack — and every report after any Sync reconnect — would
///    carry a value the controller never recorded and be rejected.
///
/// The `report` below can only succeed if `watch` recorded the SAME value
/// this `report` sends: an inconsistent client is rejected with
/// `FAILED_PRECONDITION` by `SyncSvc::report`. So this is an end-to-end pin
/// on the client's own consistency, not just an equality check on a getter.
#[tokio::test]
async fn session_generation_is_nonzero_stable_and_accepted_end_to_end() {
    let first = sync::session_generation();
    assert_ne!(
        first, 0,
        "0 is the legacy/unknown sentinel on the wire — a gateway that sends it opts itself \
         out of the session-generation gate entirely"
    );
    assert_eq!(
        first,
        sync::session_generation(),
        "session_generation() must be a per-PROCESS constant: the rotation tick's unary \
         epoch-ack Report dials its own channel and would otherwise carry a value the \
         controller's Watch never recorded"
    );

    let h = TestController::start().await;
    let g1 = enroll_one(&h, "seg-a", "10.10.1.0/24").await;
    let _g2 = enroll_one(&h, "seg-b", "10.10.2.0/24").await;

    let id = Identity {
        cert_pem: g1.cert_pem().to_string(),
        key_pem: g1.key_pem().to_string(),
        ca_bundle_pem: g1.ca_bundle_pem().to_string(),
        gateway_id: g1.id(),
        observe_key: String::new(),
        wg_private_key_b64: String::new(),
    };

    let mut client = sync::connect(&h.sync_tcp_addr().to_string(), &id)
        .await
        .expect("mTLS connect");
    // Records this process's generation against g1, controller-side.
    let stream = sync::watch(&mut client).await.expect("watch");

    // ...and the report must carry the SAME one, or the controller rejects
    // it. A fresh-per-call or per-connection nonce fails right here.
    sync::report(&mut client, 0, vec!["10.10.1.1:51820".to_string()], vec![], vec![], None)
        .await
        .expect(
            "a report from the same process that opened the Watch must be accepted — a \
             failure here means watch() and report() disagree about this process's \
             session_generation",
        );

    assert_eq!(
        first,
        sync::session_generation(),
        "the process nonce must be unchanged after a real watch+report round trip"
    );
    let _ = stream; // keep the Watch alive across the report
}
