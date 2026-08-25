//! Sync client against the real in-process controller (no netns needed).
//! ./dev.sh run "cargo test -p wiremesh-gateway --test sync_client -- --nocapture"
use wiremesh_gateway::identity::Identity;
use wiremesh_gateway::sync;
use wiremesh_gateway::uapi::base64_pub_from_priv;
use wiremesh_proto::v1::RotateKeyRequest;
use wiremesh_testkit::{enroll_one, StubGateway, TestController};

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
            let pk = String::from_utf8(
                std::process::Command::new("wg")
                    .arg("genkey")
                    .output()
                    .unwrap()
                    .stdout,
            )
            .unwrap()
            .trim()
            .to_string();
            let _ = base64_pub_from_priv(&pk).unwrap();
            pk
        },
    };

    let mut client = sync::connect(&h.sync_tcp_addr().to_string(), &id)
        .await
        .expect("mTLS connect");
    let mut stream = sync::watch(&mut client).await.expect("watch");
    let mut cur = None;
    // The first Sync message is always a snapshot, surfaced as SyncEvent::State.
    let ds = match sync::next_event(&mut stream, &mut cur)
        .await
        .expect("first msg")
        .expect("snapshot")
    {
        sync::SyncEvent::State(ds) => ds,
        sync::SyncEvent::Punch(p) => panic!("expected snapshot, got punch directive: {p:?}"),
        sync::SyncEvent::Rotate(r) => panic!("expected snapshot, got rotate directive: {r:?}"),
    };
    // Gateway A's peer is gateway B (seg-b, 10.10.2.0/24).
    assert!(
        ds.peers
            .iter()
            .any(|p| p.allowed_ips.contains(&"10.10.2.0/24".to_string())),
        "snapshot lists peer B's segment: {:?}",
        ds.peers
    );

    sync::report(&mut client, ds.policy_version, vec![], vec![], vec![], None)
        .await
        .expect("report ack");
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
    sync::report(
        &mut client,
        0,
        vec!["10.10.1.1:51820".to_string()],
        vec![],
        vec![],
        None,
    )
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

/// Build a gateway `Identity` from an enrolled `StubGateway`'s material —
/// `sync::connect` reads only the cert/key/CA fields, so the rest get
/// placeholders (same adaptation the tests above make inline).
fn identity_of(g: &StubGateway) -> Identity {
    Identity {
        cert_pem: g.cert_pem().to_string(),
        key_pem: g.key_pem().to_string(),
        ca_bundle_pem: g.ca_bundle_pem().to_string(),
        gateway_id: g.id(),
        observe_key: String::new(),
        wg_private_key_b64: String::new(),
    }
}

/// Starts a rotation for `gateway_id` and returns the new pending epoch,
/// asserting it holds the `awaiting-submission` sentinel — the row a
/// `SubmitEpochKey` swaps onto.
async fn pending_epoch_after_rotate(h: &TestController, gateway_id: u64) -> u32 {
    h.admin_client()
        .await
        .rotate_key(RotateKeyRequest { gateway_id })
        .await
        .expect("Admin.RotateKey must succeed");
    let states = h.debug_key_states(gateway_id).await;
    let (epoch, pubkey, state) = states
        .iter()
        .max_by_key(|(epoch, _, _)| *epoch)
        .unwrap_or_else(|| panic!("no GATEWAY_KEY rows after rotation: {states:?}"));
    assert_eq!(
        state, "pending",
        "the freshly rotated epoch must be pending: {states:?}"
    );
    assert_eq!(
        pubkey, "awaiting-submission",
        "the freshly rotated epoch must hold the sentinel: {states:?}"
    );
    *epoch
}

/// The pubkey currently stored for `epoch`, via `Admin.DebugKeyStates`.
async fn epoch_pubkey(h: &TestController, gateway_id: u64, epoch: u32) -> String {
    let states = h.debug_key_states(gateway_id).await;
    states
        .iter()
        .find(|(e, _, _)| *e == epoch)
        .map(|(_, pubkey, _)| pubkey.clone())
        .unwrap_or_else(|| panic!("epoch {epoch} missing for gateway {gateway_id}: {states:?}"))
}

/// (Sync session generation, gateway side — THIRD stamping site)
/// `sync::submit_epoch_key` must stamp the SAME nonzero process nonce that
/// `sync::watch` and `sync::report` stamp.
///
/// Why the sibling test above does not already cover this: it exercises
/// `watch` and `report` only. Stamping `0` in `submit_epoch_key` leaves that
/// test green, leaves `epoch_key_submit`'s controller-side suite green (its
/// stub drives its own client, not this one), and leaves the netns
/// `key_rotation` suite green — because a `0` stamp is ACCEPTED via the
/// legacy fail-open leg. Every existing assertion is satisfied by a gateway
/// that has silently opted itself out of the gate. Asserting "the submission
/// succeeded" therefore proves nothing here; succeeding is exactly the
/// sabotage's symptom.
///
/// So this test observes the transmitted value instead, by boxing it in from
/// both sides:
///
///  - **Phase A (consistency)** — after `sync::watch` recorded this process's
///    nonce, a submission over the same client must be ACCEPTED and APPLIED.
///    A stamp of any nonzero value OTHER than the process nonce (e.g. a fresh
///    random per call, or a per-connection value) conflicts with what `watch`
///    recorded and is rejected. So phase A bounds the stamped value to
///    `{0, process_nonce}`.
///  - **Phase B (nonzero)** — a second gateway whose recorded generation has
///    been SUPERSEDED by a different nonzero one must have its submission
///    REJECTED. A `0` stamp takes the `req == 0` fail-open leg and is
///    accepted, so phase B excludes `0`.
///
/// A ∧ B ⇒ the stamped value is exactly the process nonce. Phase B then reads
/// that value straight out of the controller's rejection message, which names
/// both generations — the only place the transmitted nonce is observable from
/// outside the gateway process.
///
/// That last assertion is deliberately coupled to
/// `SyncSvc::check_session_generation`'s status text. The alternative would be
/// a production accessor for "the nonce last put on the wire", which exists
/// only for tests and which a `0`-stamping regression could bypass just as
/// easily (it would report the OnceLock, not the field actually sent). Reading
/// the wire value back off the server is weaker in coupling but stronger in
/// what it proves. If the message is reworded, the `contains` assertions below
/// name what to update.
///
/// Sabotage: change `session_generation: session_generation()` to
/// `session_generation: 0` in `wiremesh_gateway::sync::submit_epoch_key`.
/// Phase B's `expect_err` fails — the submission is accepted via the fail-open
/// leg, and (had it not been) the sentinel would have been overwritten.
/// Changing it to a fresh `OsRng` value per call instead reddens phase A.
#[tokio::test]
async fn submit_epoch_key_stamps_the_same_nonzero_process_nonce_as_watch() {
    let h = TestController::start().await;
    let live = enroll_one(&h, "seg-live", "10.20.1.0/24").await;
    let superseded = enroll_one(&h, "seg-superseded", "10.20.2.0/24").await;

    let process_nonce = sync::session_generation();
    assert_ne!(
        process_nonce, 0,
        "the process nonce must be nonzero to begin with"
    );

    // --- Phase A: the submission carries the same value `watch` recorded ---
    let mut live_client = sync::connect(&h.sync_tcp_addr().to_string(), &identity_of(&live))
        .await
        .expect("mTLS connect (live gateway)");
    // This is what RECORDS the process nonce against `live` controller-side.
    let _live_watch = sync::watch(&mut live_client)
        .await
        .expect("watch (live gateway)");

    let epoch_a = pending_epoch_after_rotate(&h, live.id()).await;
    sync::submit_epoch_key(
        &mut live_client,
        epoch_a,
        "GATEWAY-SUBMITTED-A==".to_string(),
    )
    .await
    .expect(
        "a submission from the same process that opened the Watch must be accepted — a \
             failure here means submit_epoch_key stamps a DIFFERENT value than watch does \
             (per-call or per-connection instead of per-process)",
    );
    assert_eq!(
        epoch_pubkey(&h, live.id(), epoch_a).await,
        "GATEWAY-SUBMITTED-A==",
        "the accepted submission must have been APPLIED, not merely not-rejected"
    );

    // --- Phase B: that value is NOT the 0 sentinel -------------------------
    let mut superseded_client =
        sync::connect(&h.sync_tcp_addr().to_string(), &identity_of(&superseded))
            .await
            .expect("mTLS connect (superseded gateway)");
    let _superseded_watch = sync::watch(&mut superseded_client)
        .await
        .expect("watch (superseded gateway)");

    // A LATER Watch for the same gateway id registers a different nonzero
    // generation, superseding this client's — the shape of a gateway restart
    // with a submission still in flight. The stub stands in for the newer
    // process; only the recorded value matters to the gate.
    let newer_generation = superseded.session_generation();
    assert_ne!(
        newer_generation, 0,
        "the superseding generation must be nonzero"
    );
    assert_ne!(
        newer_generation, process_nonce,
        "the superseding generation must DIFFER from this process's nonce, or there is no \
         conflict for the gate to detect and phase B is vacuous (a ~1-in-2^64 collision)"
    );
    let _newer_watch = superseded.open_sync().await;

    let epoch_b = pending_epoch_after_rotate(&h, superseded.id()).await;
    let err = sync::submit_epoch_key(
        &mut superseded_client,
        epoch_b,
        "GATEWAY-SUBMITTED-B==".to_string(),
    )
    .await
    .expect_err(
        "a submission stamped with a NONZERO nonce must be REJECTED once a different nonzero \
         generation has been recorded for this gateway. Accepted means the gateway stamped 0 \
         — the legacy sentinel — and has silently opted itself out of the gate entirely",
    );

    let chain = format!("{err:#}");
    assert!(
        chain.contains("session_generation"),
        "the rejection must come from the session-generation gate, not from \
         `set_epoch_pubkey`'s own compare-and-swap: {chain}"
    );
    assert!(
        !chain.contains("no pending epoch"),
        "the epoch must have been genuinely pending — a 'no pending epoch' rejection would \
         mean this test never reached the gate at all: {chain}"
    );
    assert!(
        chain.contains(&process_nonce.to_string()),
        "the controller names the generation it received; it must be THIS PROCESS's nonce \
         ({process_nonce}), which is the value `watch` and `report` also stamp. Got: {chain}"
    );

    assert_eq!(
        epoch_pubkey(&h, superseded.id(), epoch_b).await,
        "awaiting-submission",
        "a rejected submission must leave the sentinel unwritten"
    );
}
