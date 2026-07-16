use prost::Message;
use wiremesh_proto::v1::{StateSnapshot, Peer, sync_message::Body, SyncMessage};

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
