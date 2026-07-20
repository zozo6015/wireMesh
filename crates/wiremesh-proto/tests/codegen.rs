use prost::Message;
use wiremesh_proto::v1::{StateSnapshot, Peer, sync_message::Body, SyncMessage, PunchDirective, ReportRequest};

#[test]
fn snapshot_message_roundtrips() {
    let snap = StateSnapshot { revision: 7, self_cert_pem: "PEM".into(),
        peers: vec![Peer { gateway_id: 2, segment_name: "aws".into(), ..Default::default() }],
        relays: vec!["r1:4443".into()], policy_ir: vec![], policy_version: 0,
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
            assert_eq!(s.relays, vec!["r1:4443".to_string()]);
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
    };
    let bytes = with_endpoints.encode_to_vec();
    let decoded = ReportRequest::decode(bytes.as_slice()).expect("decoding the encoded ReportRequest");
    assert_eq!(decoded, with_endpoints);

    // Empty local_endpoints must still roundtrip cleanly (old-client behavior,
    // pre-dating this additive field).
    let no_endpoints = ReportRequest { applied_version: 5, local_endpoints: vec![] };
    let bytes = no_endpoints.encode_to_vec();
    let decoded = ReportRequest::decode(bytes.as_slice()).expect("decoding the encoded ReportRequest");
    assert_eq!(decoded, no_endpoints);
}
