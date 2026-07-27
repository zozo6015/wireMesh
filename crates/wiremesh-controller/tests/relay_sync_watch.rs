//! Mesh-convergence fix cycle, task T6 (ops finding "Relay Finding B",
//! `docs/research/ops-finding-multi-gateway-convergence.md`): the controller
//! must authorize enrolled RELAY identities on the revocation-bearing
//! `Sync.Watch` — WITHOUT handing them gateway desired-state.
//!
//! Today `SyncSvc::watch` resolves the mTLS peer certificate's subject CN
//! exclusively via `Db::find_gateway_by_name` and rejects everything else
//! with `PermissionDenied: "client certificate's CN does not match any
//! enrolled gateway"`. A relay's leaf (issued by
//! `EnrollmentSvc::enroll`'s endpoint-routed branch) carries CN
//! `relay-<secret_hash_hex>` — never a `gateway.name` — so the relay's
//! denylist watch (`wiremesh_relay::lib.rs`'s `Sync.Watch` consumer, which
//! feeds `Denylist::replace_all` from the snapshot's `revoked_serials` and
//! `Denylist::union` from each delta's) is rejected outright and the
//! relay's offline revocation denylist NEVER updates after enrollment — a
//! security-relevant staleness observed live on 2026-07-27.
//!
//! Contract pinned here (all but the last test expected RED today):
//!
//!   (a) A relay that has enrolled (`--kind relay` token, endpoint-routed
//!       path) can open `Sync.Watch` with its own enrolled certificate and
//!       the stream is ACCEPTED — first message a `StateSnapshot`, exactly
//!       what the relay binary's consumer expects.
//!   (b) That watch actually carries revocation information: serials
//!       revoked BEFORE the watch opened appear in the snapshot's
//!       `revoked_serials` (the relay's `replace_all` path), and a serial
//!       revoked WHILE the watch is open arrives as a `Delta` whose
//!       `revoked_serials` contains it (the `union` path).
//!   (c) SECURITY BOUNDARY: the relay's watch must NOT receive gateway
//!       desired-state — no `Peer` payloads (snapshot `peers` / delta
//!       `upserted_peers`), no policy (`policy_ir` / `policy_version`), no
//!       `PunchDirective`s — even while gateways enroll, report endpoints,
//!       and policy exists. A relay only gets the revocation-relevant
//!       subset.
//!   (d) Regression guard (expected GREEN today, must STAY green): an
//!       ordinary GATEWAY's watch still receives its full desired-state
//!       (snapshot policy, peer-upsert deltas, revocation deltas) — the fix
//!       must scope relays down, not gateways.
//!
//! Harness mirrors `tests/sync_relays.rs` / `tests/revoke_audit.rs` /
//! `tests/policy_pipeline.rs` exactly (`wiremesh_testkit::TestController`,
//! `enroll_one`, bounded `tokio::time::timeout` waits). The relay-side mTLS
//! dial is a LOCAL helper duplicating `StubGateway`'s (private)
//! `dial_sync_with` recipe, because `wiremesh_testkit::enroll_relay`
//! discards the keypair (it predates any relay-side Sync need) — see
//! `enroll_relay_with_key` below. If the implementer prefers, a testkit
//! `StubRelay` (enroll + keep identity + `open_sync`) is the cleaner
//! long-term home for that plumbing (`enroll_relay`'s own doc comment
//! already anticipates it); these tests deliberately keep it local rather
//! than growing testkit from the test-author side.
use std::time::Duration;

use tonic::transport::{Certificate, Channel, ClientTlsConfig, Identity};
use wiremesh_proto::v1::sync_client::SyncClient;
use wiremesh_proto::v1::{
    sync_message, EnrollRequest, MintTokenRequest, RevokeCertRequest, SyncMessage, WatchRequest,
};
use wiremesh_testkit::{StubGateway, TestController};

/// Bounds every wait on a `Sync.Watch` message so a regression (stream
/// rejected, or an expected message never pushed) fails fast instead of
/// hanging the suite — same constant/rationale as `tests/sync_relays.rs` /
/// `tests/revoke_audit.rs`.
const SYNC_TIMEOUT: Duration = Duration::from_secs(5);

/// Segments + a real compiled policy, applied in one call — verbatim the
/// master-spec §5.1 worked example `tests/policy_pipeline.rs` uses, reused
/// here so test (c) can prove a relay's watch carries none of it (and test
/// (d) that a gateway's still does).
const FABRIC_WITH_POLICY: &str = r#"
segments:
  - name: proxmox-lab
    cidrs: ["10.10.0.0/16"]
  - name: aws-prod
    cidrs: ["172.16.0.0/12"]
policy:
  - from: proxmox-lab
    to: aws-prod
    rules:
      - deny:  { ports: [22], proto: tcp }
      - allow: { dst: 172.16.1.50/32, ports: [5432], proto: tcp }
      - allow: { dst: 172.16.2.0/24, ports: [443, "8000-8080"], proto: tcp }
"#;

/// An enrolled relay's full client identity — what
/// `wiremesh_testkit::enroll_relay` returns PLUS the private key it
/// currently discards, which is exactly what a Sync mTLS dial needs.
struct RelayIdentity {
    cert_pem: String,
    key_pem: String,
    ca_bundle_pem: String,
    relay_id: i64,
}

/// Mirrors `wiremesh_testkit::enroll_relay` (mint a `relay`-kind token,
/// redeem it via `Enrollment.Enroll` with `endpoint` set and `cidrs` empty)
/// but KEEPS the generated private key so the returned identity can dial
/// the controller's mTLS Sync listener — the operation under test.
async fn enroll_relay_with_key(h: &TestController, endpoint: &str) -> RelayIdentity {
    let mut admin = h.admin_client().await;
    let token = admin
        .mint_token(MintTokenRequest {
            kind: "relay".to_string(),
            bound_cidrs: vec![],
            rebind_segment_id: 0,
        })
        .await
        .expect("minting relay token for enroll_relay_with_key")
        .into_inner()
        .token;

    let (csr_pem, key_pair) = wiremesh_testkit::gen_csr("stub-relay");
    let key_pem = key_pair.serialize_pem();

    let mut enr = h.enrollment_client().await;
    let resp = enr
        .enroll(EnrollRequest {
            token,
            csr_pem,
            cidrs: vec![],
            wg_pubkey: String::new(),
            endpoint: endpoint.to_string(),
        })
        .await
        .expect("Enrollment.Enroll (relay path) failed in enroll_relay_with_key")
        .into_inner();

    RelayIdentity {
        cert_pem: resp.cert_pem,
        key_pem,
        ca_bundle_pem: resp.ca_bundle_pem,
        // The proto field is reused to carry the relay's row id — see
        // `EnrollmentSvc::enroll`'s relay branch.
        relay_id: resp.gateway_id as i64,
    }
}

/// Opens `Sync.Watch` presenting the RELAY's enrolled certificate + key —
/// the exact operation "Relay Finding B" reports as rejected. Duplicates
/// `StubGateway::dial_sync_with`'s recipe (private to testkit; see the
/// module doc comment). The TLS-level connect is `.expect`ed (the relay's
/// leaf chains to the same fabric CA, so the mTLS handshake itself must
/// succeed even today); only the application-level `watch` result is
/// returned, because THAT is the authorization decision under test.
async fn open_relay_watch(
    h: &TestController,
    relay: &RelayIdentity,
) -> Result<tonic::Streaming<SyncMessage>, tonic::Status> {
    let uri = format!("https://{}", h.sync_tcp_addr());
    let tls = ClientTlsConfig::new()
        .identity(Identity::from_pem(&relay.cert_pem, &relay.key_pem))
        .ca_certificate(Certificate::from_pem(&relay.ca_bundle_pem))
        .domain_name("127.0.0.1");
    let channel = Channel::from_shared(uri)
        .expect("controller Sync TCP addr must form a valid URI")
        .tls_config(tls)
        .expect("configuring relay mTLS: presenting its cert + trusting the controller CA")
        .connect()
        .await
        .expect(
            "the relay's mTLS handshake itself must succeed (its leaf chains to the fabric \
             CA); only the Sync.Watch authorization decision is under test",
        );
    SyncClient::new(channel)
        .watch(WatchRequest {})
        .await
        .map(|resp| resp.into_inner())
}

/// Reads the next message off `stream`, bounded by [`SYNC_TIMEOUT`].
async fn next_msg(stream: &mut tonic::Streaming<SyncMessage>) -> SyncMessage {
    tokio::time::timeout(SYNC_TIMEOUT, stream.message())
        .await
        .expect("timed out waiting for a Sync.Watch message")
        .expect("Sync.Watch stream yielded an error instead of a message")
        .expect("Sync.Watch stream ended before delivering a message")
}

/// Reads messages off `stream` until a `Delta` whose `revoked_serials`
/// contains `serial` arrives (bounded by [`SYNC_TIMEOUT`] overall),
/// returning EVERY message seen up to and including that delta — so a
/// caller can additionally assert properties of everything that preceded
/// the revocation (test (c)'s "nothing desired-state-shaped ever arrived"
/// relies on the change-broadcast being ordered: any event published BEFORE
/// the revocation that this stream forwards must arrive before the
/// revocation delta does).
async fn drain_until_revocation(
    stream: &mut tonic::Streaming<SyncMessage>,
    serial: &str,
) -> Vec<SyncMessage> {
    let deadline = tokio::time::Instant::now() + SYNC_TIMEOUT;
    let mut seen: Vec<SyncMessage> = Vec::new();
    loop {
        let remaining = deadline.saturating_duration_since(tokio::time::Instant::now());
        if remaining.is_zero() {
            panic!(
                "timed out waiting for a Delta carrying revoked serial {serial}; \
                 messages seen so far: {seen:?}"
            );
        }
        let msg = match tokio::time::timeout(remaining, stream.message()).await {
            Ok(Ok(Some(msg))) => msg,
            Ok(Ok(None)) => panic!(
                "Sync.Watch stream ended before delivering a Delta carrying revoked \
                 serial {serial}; messages seen so far: {seen:?}"
            ),
            Ok(Err(status)) => panic!(
                "Sync.Watch stream yielded an error before delivering a Delta carrying \
                 revoked serial {serial}: {status}; messages seen so far: {seen:?}"
            ),
            Err(_) => panic!(
                "timed out waiting for a Delta carrying revoked serial {serial}; \
                 messages seen so far: {seen:?}"
            ),
        };
        let is_flush = matches!(
            &msg.body,
            Some(sync_message::Body::Delta(d)) if d.revoked_serials.iter().any(|s| s == serial)
        );
        seen.push(msg);
        if is_flush {
            return seen;
        }
    }
}

/// Mirrors `tests/policy_pipeline.rs`'s `enroll_on_existing_segment`:
/// enrolls a `StubGateway` onto a segment `Admin.Apply` already created
/// (unlike `enroll_one`, which creates its own segment).
async fn enroll_on_applied_segment(h: &TestController, cidr: &str) -> StubGateway {
    let token = h
        .admin_client()
        .await
        .mint_token(MintTokenRequest {
            kind: "gateway".to_string(),
            bound_cidrs: vec![cidr.to_string()],
            rebind_segment_id: 0,
        })
        .await
        .expect("minting gateway token for enroll_on_applied_segment")
        .into_inner()
        .token;

    StubGateway::enroll(h, &token, &[cidr])
        .await
        .expect("enrolling stub gateway onto an already-applied segment")
}

/// (a) The exact operation "Relay Finding B" reports as broken: an enrolled
/// relay opening `Sync.Watch` with its own certificate. Today this fails
/// with `PermissionDenied: "client certificate's CN does not match any
/// enrolled gateway"` (the relay's CN is `relay-<secret_hash_hex>`, which
/// `Db::find_gateway_by_name` never matches). After the fix the stream must
/// be accepted and — matching what the relay binary's consumer expects —
/// open with a `StateSnapshot` as its first message.
#[tokio::test]
async fn enrolled_relay_can_open_sync_watch() {
    let h = TestController::start().await;
    let relay = enroll_relay_with_key(&h, "203.0.113.9:4443").await;
    assert!(relay.relay_id > 0, "relay enrollment must assign a row id");

    let mut stream = open_relay_watch(&h, &relay).await.expect(
        "an ENROLLED relay's Sync.Watch must be authorized (today it is rejected with \
         PermissionDenied: \"client certificate's CN does not match any enrolled \
         gateway\" — Relay Finding B)",
    );

    let first = next_msg(&mut stream).await;
    match first.body {
        Some(sync_message::Body::Snapshot(_)) => {}
        other => panic!(
            "the relay's Sync.Watch must open with a StateSnapshot (what the relay \
             binary's denylist consumer replace_all's from), got: {other:?}"
        ),
    }
}

/// (b) The denylist-update path end to end: a serial revoked BEFORE the
/// relay's watch opened must be in the snapshot's `revoked_serials` (the
/// relay's `Denylist::replace_all` input), and a serial revoked WHILE the
/// watch is open must arrive in a `Delta`'s `revoked_serials` (the
/// `Denylist::union` input) — this is the security-relevant staleness the
/// finding is about: without it, a revoked gateway cert keeps bridging
/// traffic through the relay until the relay restarts.
#[tokio::test]
async fn relay_watch_receives_revocations_in_snapshot_and_delta() {
    let h = TestController::start().await;
    let victim_pre = wiremesh_testkit::enroll_one(&h, "aws", "10.0.0.0/16").await;
    let victim_live = wiremesh_testkit::enroll_one(&h, "gcp", "10.1.0.0/16").await;
    let relay = enroll_relay_with_key(&h, "203.0.113.9:4443").await;

    // Revoke the first victim BEFORE the relay's watch opens — this must
    // land in the snapshot.
    let pre_serial = victim_pre
        .cert_serial()
        .expect("reading the pre-revoked victim's cert serial");
    h.admin_client()
        .await
        .revoke_cert(RevokeCertRequest {
            serial: pre_serial.clone(),
        })
        .await
        .expect("Admin.RevokeCert (pre-watch victim) must succeed");

    let mut stream = open_relay_watch(&h, &relay)
        .await
        .expect("an enrolled relay's Sync.Watch must be authorized (test (a) pins this)");

    let snap = match next_msg(&mut stream).await.body {
        Some(sync_message::Body::Snapshot(s)) => s,
        other => panic!("expected the relay's first Sync.Watch message to be a StateSnapshot, got: {other:?}"),
    };
    assert!(
        snap.revoked_serials.contains(&pre_serial),
        "the relay's snapshot must carry the already-revoked serial {pre_serial} in \
         revoked_serials (the relay's replace_all path), got: {:?}",
        snap.revoked_serials
    );

    // Revoke the second victim WHILE the relay's watch is open — this must
    // arrive as a Delta carrying the serial.
    let live_serial = victim_live
        .cert_serial()
        .expect("reading the live-revoked victim's cert serial");
    h.admin_client()
        .await
        .revoke_cert(RevokeCertRequest {
            serial: live_serial.clone(),
        })
        .await
        .expect("Admin.RevokeCert (live victim) must succeed");

    // `drain_until_revocation` panics with everything seen if no such delta
    // arrives within the timeout — the exact staleness under test.
    let _ = drain_until_revocation(&mut stream, &live_serial).await;
}

/// (c) SECURITY BOUNDARY: a relay is not a gateway and must not receive
/// gateway desired-state on its watch — no `Peer` payloads (snapshot
/// `peers` / delta `upserted_peers`), no compiled policy
/// (`policy_ir`/`policy_version`), no `PunchDirective`s. Topology chosen so
/// desired-state DOES exist and DOES mutate while the relay watches: a
/// compiled policy is applied and a gateway enrolled before the watch opens
/// (snapshot must omit both), then a second gateway enrolls
/// (`GatewayEnrolled` → peer-upsert delta for gateways) and the first
/// reports local endpoints (`EndpointObserved` → peer-upsert delta with
/// keys + candidates) while the watch is open. A final revocation acts as
/// the ordered flush: the change-broadcast delivers events in publish
/// order, so once the revocation delta has arrived, any desired-state delta
/// the stream WOULD have forwarded from the earlier mutations must already
/// be in `seen` — no bare negative-timing wait needed.
///
/// NOTE for the implementer: the relay is deliberately enrolled FIRST here,
/// so its row id (1) collides with the first GATEWAY's id in the broker's
/// gateway-id-keyed registry — relay and gateway ids are separate sqlite
/// sequences and DO overlap. Authorizing relays by reusing the gateway
/// watch path unscoped would register the relay's punch channel under
/// "gateway 1" (and count it in `Broker::connected_gateway_ids`, which
/// rotation's expected-peer set reads). The no-PunchDirective assertion
/// below is the observable guard for that hazard.
#[tokio::test]
async fn relay_watch_carries_no_gateway_desired_state() {
    let h = TestController::start().await;

    // Relay FIRST — forces relay_id == 1 to collide with gw ids (see NOTE).
    let relay = enroll_relay_with_key(&h, "203.0.113.9:4443").await;

    // Real desired-state exists before the watch opens: a compiled policy
    // and an enrolled gateway.
    let diff = h.apply(FABRIC_WITH_POLICY).await;
    assert!(
        diff.policy_updated,
        "harness precondition: applying FABRIC_WITH_POLICY must compile a policy, got: {diff:?}"
    );
    let gw1 = enroll_on_applied_segment(&h, "10.10.0.0/16").await;

    let mut stream = open_relay_watch(&h, &relay)
        .await
        .expect("an enrolled relay's Sync.Watch must be authorized (test (a) pins this)");

    let snap = match next_msg(&mut stream).await.body {
        Some(sync_message::Body::Snapshot(s)) => s,
        other => panic!("expected the relay's first Sync.Watch message to be a StateSnapshot, got: {other:?}"),
    };
    assert!(
        snap.peers.is_empty(),
        "a relay's snapshot must carry NO gateway peers (desired-state), got: {:?}",
        snap.peers
    );
    assert!(
        snap.policy_ir.is_empty() && snap.policy_version == 0,
        "a relay's snapshot must carry NO compiled policy, got policy_version {} with {} \
         bytes of policy_ir",
        snap.policy_version,
        snap.policy_ir.len()
    );

    // Desired-state mutations while the relay watches: a new gateway
    // enrolls (GatewayEnrolled) and gw1 reports a local endpoint
    // (EndpointObserved) — each pushes a peer-upsert delta to GATEWAY
    // watchers.
    let gw2 = enroll_on_applied_segment(&h, "172.16.0.0/12").await;
    gw1.report(0, &["10.10.0.5:51820"])
        .await
        .expect("gw1's Sync.Report with a local endpoint must succeed");

    // Ordered flush: revoke gw2's cert; the relay MUST see this (test (b))
    // and must see it AFTER anything the stream forwarded from the earlier
    // mutations.
    let flush_serial = gw2
        .cert_serial()
        .expect("reading gw2's cert serial for the flush revocation");
    h.admin_client()
        .await
        .revoke_cert(RevokeCertRequest {
            serial: flush_serial.clone(),
        })
        .await
        .expect("Admin.RevokeCert (flush) must succeed");

    let seen = drain_until_revocation(&mut stream, &flush_serial).await;

    for msg in &seen {
        match &msg.body {
            Some(sync_message::Body::Delta(d)) => {
                assert!(
                    d.upserted_peers.is_empty(),
                    "a relay's watch must never carry peer upserts (gateway \
                     desired-state), got delta: {d:?}"
                );
                assert!(
                    d.removed_peer_ids.is_empty(),
                    "a relay's watch must never carry peer removals (gateway \
                     desired-state), got delta: {d:?}"
                );
                assert!(
                    d.policy_ir.is_empty() && d.policy_version == 0,
                    "a relay's watch must never carry compiled policy, got delta: {d:?}"
                );
            }
            Some(sync_message::Body::Punch(p)) => panic!(
                "a relay's watch must never receive a PunchDirective (broker \
                 registration under a colliding gateway id — see this test's NOTE), \
                 got: {p:?}"
            ),
            Some(sync_message::Body::Rotate(r)) => panic!(
                "a relay's watch must never receive a RotateDirective (gateway key \
                 rotation is gateway desired-state), got: {r:?}"
            ),
            Some(sync_message::Body::Snapshot(s)) => panic!(
                "the relay's stream must not deliver a second StateSnapshot \
                 mid-stream, got: {s:?}"
            ),
            None => panic!("SyncMessage with an empty body on the relay's watch"),
        }
    }
}

/// (d) Regression guard — expected GREEN today and it must STAY green: the
/// fix scopes RELAYS down, it must not touch what a GATEWAY's watch
/// receives. With a relay enrolled and a compiled policy applied, a
/// gateway's snapshot still carries the full desired-state (policy), a
/// second gateway's enrollment still arrives as a peer-upsert delta, and a
/// revocation still arrives in `revoked_serials`.
#[tokio::test]
async fn gateway_watch_still_receives_full_desired_state() {
    let h = TestController::start().await;

    // Relay present the whole time — a gateway's view must be unaffected.
    let _relay = enroll_relay_with_key(&h, "203.0.113.9:4443").await;

    let diff = h.apply(FABRIC_WITH_POLICY).await;
    assert!(
        diff.policy_updated,
        "harness precondition: applying FABRIC_WITH_POLICY must compile a policy, got: {diff:?}"
    );
    let gw1 = enroll_on_applied_segment(&h, "10.10.0.0/16").await;

    let mut stream = gw1.open_sync().await;
    let snap = match next_msg(&mut stream).await.body {
        Some(sync_message::Body::Snapshot(s)) => s,
        other => panic!("expected gw1's first Sync.Watch message to be a StateSnapshot, got: {other:?}"),
    };
    assert_eq!(
        snap.policy_version, 1,
        "a GATEWAY's snapshot must still carry the compiled policy version"
    );
    assert!(
        !snap.policy_ir.is_empty(),
        "a GATEWAY's snapshot must still carry the compiled policy_ir bytes"
    );

    // A second gateway enrolling must still reach gw1 as a peer-upsert
    // delta.
    let gw2 = enroll_on_applied_segment(&h, "172.16.0.0/12").await;
    let deadline = tokio::time::Instant::now() + SYNC_TIMEOUT;
    loop {
        let remaining = deadline.saturating_duration_since(tokio::time::Instant::now());
        if remaining.is_zero() {
            panic!(
                "timed out waiting for gw1 to receive the peer-upsert delta for gw2 \
                 (id {})",
                gw2.id()
            );
        }
        let msg = tokio::time::timeout(remaining, stream.message())
            .await
            .expect("timed out waiting for gw1's peer-upsert delta")
            .expect("gw1's Sync.Watch stream yielded an error")
            .expect("gw1's Sync.Watch stream ended before the peer-upsert delta");
        if let Some(sync_message::Body::Delta(d)) = &msg.body {
            if d.upserted_peers.iter().any(|p| p.gateway_id == gw2.id()) {
                break;
            }
        }
    }

    // And a revocation must still reach gw1's denylist view.
    let serial = gw2
        .cert_serial()
        .expect("reading gw2's cert serial for the gateway-side revocation check");
    h.admin_client()
        .await
        .revoke_cert(RevokeCertRequest {
            serial: serial.clone(),
        })
        .await
        .expect("Admin.RevokeCert must succeed");
    let _ = drain_until_revocation(&mut stream, &serial).await;
}
