//! Enforcer wiring on wg0: apply an IR, assert allow/deny + counters.
//! ./dev.sh run "cargo test -p wiremesh-gateway --test enforce_netns \
//!   --features netns-tests -- --test-threads=1 --nocapture"
#![cfg(feature = "netns-tests")]
use wiremesh_gateway::enforce::GatewayEnforcer;
use wiremesh_gateway::state::DesiredState;
use wiremesh_testkit::netns::{join_netns, wg_lab};

#[test]
fn apply_if_changed_applies_once_per_version() {
    let (lab, _a, b) = wg_lab("gwenf");
    join_netns(&b.name).expect("join b");
    let mut enf = GatewayEnforcer::attach("wg0").expect("probe wg0");

    // First apply: an allow-nothing IR (default deny).
    let mut ds = DesiredState {
        policy_version: 1,
        policy_ir: br#"{"schema":1,"version":1,"blocks":[]}"#.to_vec(),
        ..Default::default()
    };
    assert!(enf.apply_if_changed(&ds).unwrap(), "first apply happens");
    assert!(
        !enf.apply_if_changed(&ds).unwrap(),
        "same version is a no-op"
    );

    // Bump version -> applies again.
    ds.policy_version = 2;
    assert!(enf.apply_if_changed(&ds).unwrap(), "new version re-applies");
    drop(lab);
}
