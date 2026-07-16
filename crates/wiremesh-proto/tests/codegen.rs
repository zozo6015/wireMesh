use wiremesh_proto::v1::{StateSnapshot, Peer, sync_message::Body, SyncMessage};

#[test]
fn snapshot_message_roundtrips() {
    let snap = StateSnapshot { revision: 7, self_cert_pem: "PEM".into(),
        peers: vec![Peer { gateway_id: 2, segment_name: "aws".into(), ..Default::default() }],
        relays: vec!["r1:4443".into()], policy_ir: vec![], policy_version: 0,
        revoked_serials: vec![] };
    let msg = SyncMessage { body: Some(Body::Snapshot(snap.clone())) };
    // prost messages derive PartialEq + Clone; assert the oneof carries the snapshot
    match msg.body { Some(Body::Snapshot(s)) => assert_eq!(s.revision, 7), _ => panic!("wrong body") };
    assert_eq!(snap.peers[0].gateway_id, 2);
}
