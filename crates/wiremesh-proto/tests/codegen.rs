#![allow(deprecated)] // constructing StateSnapshot/Delta requires setting deprecated_relays (field 4)
use prost::Message;
use wiremesh_proto::v1::{
    StateSnapshot, Peer, sync_message::Body, SyncMessage, PunchDirective, ReportRequest,
    RelayInfo, RelayHealth, Delta, EnrollRequest, RotateDirective, SubmitEpochKeyRequest,
    EpochAck, PeerPath, WatchRequest,
};

#[test]
fn snapshot_message_roundtrips() {
    let snap = StateSnapshot { revision: 7, self_cert_pem: "PEM".into(),
        peers: vec![Peer { gateway_id: 2, segment_name: "aws".into(), ..Default::default() }],
        deprecated_relays: vec![],
        relay_infos: vec![RelayInfo { relay_id: 7, endpoint: "r1:4443".into() }], policy_ir: vec![], policy_version: 0,
        revoked_serials: vec![] };
    let msg = SyncMessage { body: Some(Body::Snapshot(snap.clone())) };

    // A GENUINE wire roundtrip: encode to protobuf bytes and decode them
    // back, rather than just re-matching the same in-memory struct the
    // `msg` above already wraps (which would prove nothing about the
    // generated codec). This is what actually exercises `build.rs`'s
    // codegen.
    let bytes = msg.encode_to_vec();
    let decoded = SyncMessage::decode(bytes.as_slice()).expect("decoding the encoded SyncMessage");

    // Assert against `decoded` — the value that actually survived the
    // encode/decode roundtrip — not `snap`/`msg`, which never left memory.
    match decoded.body {
        Some(Body::Snapshot(s)) => {
            assert_eq!(s.revision, 7);
            assert_eq!(s.peers[0].gateway_id, 2);
            assert_eq!(s.peers[0].segment_name, "aws");
            assert_eq!(s.self_cert_pem, "PEM");
            assert_eq!(s.relay_infos[0].relay_id, 7);
            assert_eq!(s.relay_infos[0].endpoint, "r1:4443");
            assert!(s.deprecated_relays.is_empty());
        }
        other => panic!("wrong body: {other:?}"),
    }
}

#[test]
fn punch_directive_message_roundtrips() {
    let punch = PunchDirective {
        peer_gateway_id: 7,
        candidates: vec!["198.51.100.2:51820".into()],
        go_unix_ms: 123,
    };
    let msg = SyncMessage { body: Some(Body::Punch(punch.clone())) };

    // Genuine wire roundtrip (see rationale in snapshot_message_roundtrips
    // above): encode to protobuf bytes, decode them back, and assert
    // against the decoded value.
    let bytes = msg.encode_to_vec();
    let decoded = SyncMessage::decode(bytes.as_slice()).expect("decoding the encoded SyncMessage");

    match decoded.body {
        Some(Body::Punch(p)) => assert_eq!(p, punch),
        other => panic!("wrong body: {other:?}"),
    }
}

#[test]
fn report_request_local_endpoints_roundtrips() {
    let with_endpoints = ReportRequest {
        applied_version: 5,
        local_endpoints: vec!["10.0.0.5:51820".into()],
        relay_health: vec![],
        epoch_acks: vec![],
        peer_paths: vec![],
        peer_paths_snapshot: false,
        session_generation: 0,
    };
    let bytes = with_endpoints.encode_to_vec();
    let decoded = ReportRequest::decode(bytes.as_slice()).expect("decoding the encoded ReportRequest");
    assert_eq!(decoded, with_endpoints);

    // Empty local_endpoints must still roundtrip cleanly (old-client behavior,
    // pre-dating this additive field).
    let no_endpoints = ReportRequest {
        applied_version: 5,
        local_endpoints: vec![],
        relay_health: vec![],
        epoch_acks: vec![],
        peer_paths: vec![],
        peer_paths_snapshot: false,
        session_generation: 0,
    };
    let bytes = no_endpoints.encode_to_vec();
    let decoded = ReportRequest::decode(bytes.as_slice()).expect("decoding the encoded ReportRequest");
    assert_eq!(decoded, no_endpoints);
}

#[test]
fn state_snapshot_relay_infos_roundtrips_multiple_relay_infos() {
    // (4c review fix) The structured relay data lives in `relay_infos`
    // (field 8, `repeated RelayInfo`) — a NEW field, added rather than
    // repurposing field 4 (`deprecated_relays`, kept at its ORIGINAL
    // `repeated string` type; see `sync.proto`'s doc comment on that field
    // for why changing an existing field's wire type is a hazard). Confirm
    // two distinct relays, each with both fields set, survive a genuine
    // wire roundtrip in the new field, and that the deprecated field still
    // roundtrips cleanly as an empty (unused) `repeated string`.
    let snap = StateSnapshot {
        revision: 11,
        self_cert_pem: "PEM".into(),
        peers: vec![],
        deprecated_relays: vec![],
        relay_infos: vec![
            RelayInfo { relay_id: 1, endpoint: "relay-a.example:4443".into() },
            RelayInfo { relay_id: 2, endpoint: "relay-b.example:4443".into() },
        ],
        policy_ir: vec![],
        policy_version: 0,
        revoked_serials: vec![],
    };

    let bytes = snap.encode_to_vec();
    let decoded = StateSnapshot::decode(bytes.as_slice()).expect("decoding the encoded StateSnapshot");

    assert_eq!(decoded.relay_infos.len(), 2);
    assert_eq!(decoded.relay_infos[0].relay_id, 1);
    assert_eq!(decoded.relay_infos[0].endpoint, "relay-a.example:4443");
    assert_eq!(decoded.relay_infos[1].relay_id, 2);
    assert_eq!(decoded.relay_infos[1].endpoint, "relay-b.example:4443");
    assert!(
        decoded.deprecated_relays.is_empty(),
        "deprecated_relays (field 4, legacy repeated string) must still roundtrip as empty \
         when unused"
    );
}

#[test]
fn delta_relay_infos_roundtrips_relay_info() {
    // See `state_snapshot_relay_infos_roundtrips_multiple_relay_infos` above
    // — `Delta` gets the identical field-8 treatment as `StateSnapshot`.
    let delta = Delta {
        revision: 12,
        upserted_peers: vec![],
        removed_peer_ids: vec![],
        deprecated_relays: vec![],
        relay_infos: vec![RelayInfo { relay_id: 3, endpoint: "relay-c.example:4443".into() }],
        relays_updated: true,
        policy_ir: vec![],
        policy_version: 0,
        revoked_serials: vec![],
    };

    let bytes = delta.encode_to_vec();
    let decoded = Delta::decode(bytes.as_slice()).expect("decoding the encoded Delta");

    assert_eq!(decoded.relay_infos.len(), 1);
    assert_eq!(decoded.relay_infos[0].relay_id, 3);
    assert_eq!(decoded.relay_infos[0].endpoint, "relay-c.example:4443");
    assert!(decoded.deprecated_relays.is_empty());
    assert!(decoded.relays_updated, "relays_updated=true must roundtrip");
}

#[test]
fn delta_relays_updated_roundtrips_true_and_false() {
    // (4c CR round 2) `Delta.relays_updated` (field 9) is the presence flag
    // that lets `apply_delta` (gateway side) distinguish "this delta
    // authoritatively updates the relay set, possibly to empty" from "this
    // is a sparse, non-relay delta" — both values must survive the wire,
    // not just default-false.
    let with_update = Delta { relays_updated: true, ..Default::default() };
    let decoded = Delta::decode(with_update.encode_to_vec().as_slice())
        .expect("decoding the encoded Delta (relays_updated: true)");
    assert!(decoded.relays_updated);

    let sparse = Delta { relays_updated: false, ..Default::default() };
    let decoded = Delta::decode(sparse.encode_to_vec().as_slice())
        .expect("decoding the encoded Delta (relays_updated: false)");
    assert!(!decoded.relays_updated);
}

#[test]
fn report_request_relay_health_roundtrips() {
    // ReportRequest gains `repeated RelayHealth relay_health = 3;` (4c Task
    // 1) so gateways can tell the controller which relays they can
    // currently reach — one healthy, one not, to prove `healthy` isn't just
    // defaulting true.
    let report = ReportRequest {
        applied_version: 9,
        local_endpoints: vec!["10.0.0.5:51820".into()],
        relay_health: vec![
            RelayHealth { relay_id: 1, healthy: true },
            RelayHealth { relay_id: 2, healthy: false },
        ],
        epoch_acks: vec![],
        peer_paths: vec![],
        peer_paths_snapshot: false,
        session_generation: 0,
    };

    let bytes = report.encode_to_vec();
    let decoded = ReportRequest::decode(bytes.as_slice()).expect("decoding the encoded ReportRequest");

    assert_eq!(decoded.relay_health.len(), 2);
    assert_eq!(decoded.relay_health[0].relay_id, 1);
    assert_eq!(decoded.relay_health[0].healthy, true);
    assert_eq!(decoded.relay_health[1].relay_id, 2);
    assert_eq!(decoded.relay_health[1].healthy, false);
}

#[test]
fn enroll_request_endpoint_roundtrips() {
    // EnrollRequest gains `string endpoint = 5;` (4c Task 1) so a gateway
    // can advertise a routable endpoint at enrollment time. Non-empty value
    // survives a genuine wire roundtrip.
    let with_endpoint = EnrollRequest {
        token: "tok".into(),
        csr_pem: "CSR".into(),
        cidrs: vec!["10.1.0.0/24".into()],
        wg_pubkey: "wgpubkey==".into(),
        endpoint: "203.0.113.9:51820".into(),
    };
    let bytes = with_endpoint.encode_to_vec();
    let decoded = EnrollRequest::decode(bytes.as_slice()).expect("decoding the encoded EnrollRequest");
    assert_eq!(decoded.endpoint, "203.0.113.9:51820");
    assert_eq!(decoded.token, "tok");
    assert_eq!(decoded.csr_pem, "CSR");
    assert_eq!(decoded.cidrs, vec!["10.1.0.0/24".to_string()]);
    assert_eq!(decoded.wg_pubkey, "wgpubkey==");

    // A default (empty-string) endpoint must still decode cleanly — this is
    // an additive field, so old-client requests that never set it must not
    // break.
    let no_endpoint = EnrollRequest {
        token: "tok".into(),
        csr_pem: "CSR".into(),
        cidrs: vec![],
        wg_pubkey: "wgpubkey==".into(),
        endpoint: String::new(),
    };
    let bytes = no_endpoint.encode_to_vec();
    let decoded = EnrollRequest::decode(bytes.as_slice()).expect("decoding the encoded EnrollRequest");
    assert_eq!(decoded.endpoint, "");
}

#[test]
fn rotate_directive_message_roundtrips() {
    // Key-rotation Task 1: SyncMessage.body gains a fourth oneof variant,
    // RotateDirective, the controller-issued instruction that tells a
    // gateway to begin publishing/accepting a new key epoch. Genuine wire
    // roundtrip (see rationale in snapshot_message_roundtrips above).
    let rotate = RotateDirective { epoch: 5 };
    let msg = SyncMessage { body: Some(Body::Rotate(rotate.clone())) };

    let bytes = msg.encode_to_vec();
    let decoded = SyncMessage::decode(bytes.as_slice()).expect("decoding the encoded SyncMessage");

    match decoded.body {
        Some(Body::Rotate(r)) => assert_eq!(r.epoch, 5),
        other => panic!("wrong body: {other:?}"),
    }
}

#[test]
fn submit_epoch_key_request_roundtrips() {
    // Key-rotation Task 1: a gateway submits its newly generated per-epoch
    // WireGuard public key to the controller via SubmitEpochKeyRequest.
    let req = SubmitEpochKeyRequest { epoch: 5, pubkey: "REALKEY==".into() };

    let bytes = req.encode_to_vec();
    let decoded = SubmitEpochKeyRequest::decode(bytes.as_slice())
        .expect("decoding the encoded SubmitEpochKeyRequest");

    assert_eq!(decoded, req);
}

#[test]
fn report_request_epoch_acks_roundtrips() {
    // Key-rotation Task 1: ReportRequest gains `repeated EpochAck
    // epoch_acks = 4;` so a gateway can tell the controller which peers it
    // has confirmed are live on a given key epoch (make-before-break
    // corroboration). One live ack, one not-yet-live ack, to prove `live`
    // isn't just defaulting true.
    let with_acks = ReportRequest {
        applied_version: 9,
        local_endpoints: vec!["10.0.0.5:51820".into()],
        relay_health: vec![],
        epoch_acks: vec![
            EpochAck { peer_gateway_id: 1, epoch: 6, live: true },
            EpochAck { peer_gateway_id: 2, epoch: 6, live: false },
        ],
        peer_paths: vec![],
        peer_paths_snapshot: false,
        session_generation: 0,
    };

    let bytes = with_acks.encode_to_vec();
    let decoded = ReportRequest::decode(bytes.as_slice()).expect("decoding the encoded ReportRequest");

    assert_eq!(decoded.epoch_acks.len(), 2);
    assert_eq!(decoded.epoch_acks[0].peer_gateway_id, 1);
    assert_eq!(decoded.epoch_acks[0].epoch, 6);
    assert_eq!(decoded.epoch_acks[0].live, true);
    assert_eq!(decoded.epoch_acks[1].peer_gateway_id, 2);
    assert_eq!(decoded.epoch_acks[1].epoch, 6);
    assert_eq!(decoded.epoch_acks[1].live, false);

    // Empty epoch_acks must still roundtrip cleanly (additive field,
    // old-client behavior).
    let no_acks = ReportRequest {
        applied_version: 9,
        local_endpoints: vec!["10.0.0.5:51820".into()],
        relay_health: vec![],
        epoch_acks: vec![],
        peer_paths: vec![],
        peer_paths_snapshot: false,
        session_generation: 0,
    };
    let bytes = no_acks.encode_to_vec();
    let decoded = ReportRequest::decode(bytes.as_slice()).expect("decoding the encoded ReportRequest");
    assert_eq!(decoded, no_acks);
}

#[test]
fn report_request_peer_paths_roundtrips() {
    // Directive-storm fix (FIX A): ReportRequest gains `repeated PeerPath
    // peer_paths = 5;` with `message PeerPath { uint64 peer_gateway_id = 1;
    // string state = 2; }` so a gateway can tell the controller its current
    // per-peer path state (the lowercase `PathState::as_str()` label) and
    // the broker can stop re-punching pairs that are already settled. Two
    // distinct states, to prove `state` is a real per-entry string and not
    // a defaulted value.
    //
    // CodeRabbit follow-up: `bool peer_paths_snapshot = 6;` disambiguates a
    // NEW client's snapshot report (true — `peer_paths` is the reporter's
    // COMPLETE current path map, empty meaning "no tracked paths, clear my
    // stored states") from an old client / the rotation-tick epoch-ack
    // unary report (false — not a path snapshot, must never wipe stored
    // states). `true` must survive the wire; absent/default must decode
    // `false` (old-client requests never set it).
    let with_paths = ReportRequest {
        applied_version: 9,
        local_endpoints: vec!["10.0.0.5:51820".into()],
        relay_health: vec![],
        epoch_acks: vec![],
        peer_paths: vec![
            PeerPath { peer_gateway_id: 2, state: "direct".into() },
            PeerPath { peer_gateway_id: 3, state: "connecting".into() },
        ],
        peer_paths_snapshot: true,
        session_generation: 0,
    };

    let bytes = with_paths.encode_to_vec();
    let decoded = ReportRequest::decode(bytes.as_slice()).expect("decoding the encoded ReportRequest");

    assert_eq!(decoded.peer_paths.len(), 2);
    assert_eq!(decoded.peer_paths[0].peer_gateway_id, 2);
    assert_eq!(decoded.peer_paths[0].state, "direct");
    assert_eq!(decoded.peer_paths[1].peer_gateway_id, 3);
    assert_eq!(decoded.peer_paths[1].state, "connecting");
    assert!(
        decoded.peer_paths_snapshot,
        "peer_paths_snapshot=true (a new client's snapshot report) must roundtrip"
    );

    // Empty peer_paths must still roundtrip cleanly (additive field,
    // old-client behavior — an empty list must decode as today's request),
    // and the unset snapshot flag must decode as false.
    let no_paths = ReportRequest {
        applied_version: 9,
        local_endpoints: vec!["10.0.0.5:51820".into()],
        relay_health: vec![],
        epoch_acks: vec![],
        peer_paths: vec![],
        peer_paths_snapshot: false,
        session_generation: 0,
    };
    let bytes = no_paths.encode_to_vec();
    let decoded = ReportRequest::decode(bytes.as_slice()).expect("decoding the encoded ReportRequest");
    assert_eq!(decoded, no_paths);
    assert!(
        !decoded.peer_paths_snapshot,
        "an old-client request (flag never set) must decode peer_paths_snapshot=false"
    );
}

#[test]
fn session_generation_roundtrips_on_watch_and_report() {
    // (Sync session generation) `WatchRequest` gains `uint64
    // session_generation = 1;` — its FIRST field ever, on a message that was
    // deliberately empty — and `ReportRequest` gains `uint64
    // session_generation = 7;`. The gateway stamps the SAME per-boot nonce on
    // both, and the controller rejects a Report whose value conflicts with
    // the one recorded at that gateway's last Watch open.
    //
    // Two properties, and the SECOND is the load-bearing one:
    //
    //  1. A nonzero value survives a genuine wire roundtrip on both messages
    //     — otherwise the controller could never see a conflict at all.
    //  2. An ABSENT field decodes to 0. Proto3 does not emit a zero scalar,
    //     so a legacy client (which has no such field) and a new client
    //     sending 0 are byte-identical on the wire — and 0 is exactly the
    //     "unknown/legacy" sentinel the controller's reject predicate treats
    //     as "no opinion, accept". If an absent field decoded to anything
    //     else, every legacy client's Report would start being rejected.
    //     Decoded here from genuinely EMPTY bytes, which is what an old
    //     client's `WatchRequest{}` actually puts on the wire.

    // A value with bits set across the full u64 range (not a small int), so a
    // narrowed/truncated field would be caught rather than surviving by luck.
    let nonce: u64 = 0xDEAD_BEEF_CAFE_F00D;

    let watch = WatchRequest { session_generation: nonce };
    let decoded = WatchRequest::decode(watch.encode_to_vec().as_slice())
        .expect("decoding the encoded WatchRequest");
    assert_eq!(
        decoded.session_generation, nonce,
        "WatchRequest.session_generation must survive the wire intact — the controller \
         records exactly this value and compares later Reports against it"
    );

    let report = ReportRequest {
        applied_version: 9,
        local_endpoints: vec!["10.0.0.5:51820".into()],
        relay_health: vec![],
        epoch_acks: vec![],
        peer_paths: vec![],
        peer_paths_snapshot: false,
        session_generation: nonce,
    };
    let decoded = ReportRequest::decode(report.encode_to_vec().as_slice())
        .expect("decoding the encoded ReportRequest");
    assert_eq!(
        decoded.session_generation, nonce,
        "ReportRequest.session_generation must survive the wire intact"
    );
    assert_eq!(decoded, report, "no other ReportRequest field may be disturbed");

    // Absent (legacy client) => 0, on both messages.
    let decoded = WatchRequest::decode([].as_slice())
        .expect("an empty WatchRequest (the legacy client's literal wire form) must decode");
    assert_eq!(
        decoded.session_generation, 0,
        "an absent WatchRequest.session_generation must decode as the 0 legacy/unknown \
         sentinel — the controller records 0 and its gate stays inert for that gateway"
    );

    let decoded = ReportRequest::decode([].as_slice())
        .expect("an empty ReportRequest must decode");
    assert_eq!(
        decoded.session_generation, 0,
        "an absent ReportRequest.session_generation must decode as the 0 legacy/unknown \
         sentinel — a 0 on either side is ACCEPTED, so legacy clients keep working"
    );
}
