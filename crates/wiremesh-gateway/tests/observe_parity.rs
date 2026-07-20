//! The gateway's probe must be accepted by the REAL controller observe endpoint,
//! proving the replicated codec matches byte-for-byte.
//! ./dev.sh run "cargo test -p wiremesh-gateway --test observe_parity -- --nocapture"
use wiremesh_gateway::observe;
use wiremesh_testkit::{enroll_one, TestController};

#[tokio::test]
async fn controller_accepts_gateway_probe_and_records_candidate() {
    let h = TestController::start().await;
    let g = enroll_one(&h, "seg-a", "10.10.1.0/24").await;
    let observe_addr = h.observe_addr();
    let gid = g.id();
    let key = g.observe_key();

    // Send the gateway's authenticated probe from a blocking task.
    let observed = tokio::task::spawn_blocking(move || {
        observe::report_once(0, observe_addr, &key, gid)
    })
    .await
    .unwrap()
    .expect("probe accepted + echoed");

    assert!(observed.port() != 0, "controller echoed a concrete observed addr: {observed}");
    // The controller should now expose this as the gateway's candidate to peers.
    // (Verified indirectly: a second enrolled gateway sees it in its snapshot —
    //  covered end-to-end in the mesh milestone; here we assert the echo alone.)
}
