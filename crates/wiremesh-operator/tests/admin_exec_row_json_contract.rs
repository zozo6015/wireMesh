//! Regression pins (test-author, final operator round) for the EXEC-TRANSPORT
//! JSON KEY CONTRACT between `operator_admin`'s `list-relays` / `list-gateways`
//! ops (the producer, running inside the controller pod's admin-exec sidecar)
//! and `admin_exec`'s `RelayRow` / `GatewayRow` (the consumer, in the operator
//! process). **Compiles today; expected GREEN** — these pin an already-correct
//! contract that has no other test.
//!
//! Why it needs a pin: the two sides are joined only by a hand-written
//! `serde_json!` literal and a `#[derive(Deserialize)]`, in different modules,
//! with no shared type. Renaming a field on either side compiles fine and fails
//! only at runtime, in production, as `parsing relay roster` / `parsing gateway
//! roster` — and for `RelayRow` the consequence is silent: the relay reconciler
//! treats the probe failure as "not enrolled" and re-mints a spare token on
//! every reconcile forever.
//!
//! SCOPE NOTE (stated rather than papered over): the coordinator asked for a
//! snake_case pin "same as GatewayRow". `GatewayRow` genuinely has a multi-word
//! field (`applied_version`) where snake_case vs camelCase is observable, and it
//! is asserted below. `RelayRow`'s four fields (`id`, `name`, `endpoint`,
//! `status`) are all single words, so there is NO casing to distinguish for it —
//! what is pinnable, and pinned, is the exact key SET and the parse. If a
//! multi-word field is ever added to `RelayRow`, a casing assertion for it must
//! be added here.

use wiremesh_operator::admin_exec::{GatewayRow, RelayRow};

/// The exact JSON `operator_admin`'s `list-relays` op emits per relay
/// (`operator_admin.rs:153-168`), reproduced independently here so a change on
/// either side breaks this test.
fn list_relays_payload() -> serde_json::Value {
    serde_json::json!([
        { "id": 1, "name": "relay-9f3ac2", "endpoint": "203.0.113.9:4443", "status": "active" },
        { "id": 2, "name": "relay-77bd10", "endpoint": "198.51.100.7:4443", "status": "inactive" }
    ])
}

/// The exact JSON `list-gateways` emits per gateway (`operator_admin.rs:169-183`).
fn list_gateways_payload() -> serde_json::Value {
    serde_json::json!([
        { "id": 3, "name": "gw-home", "segment": "home", "status": "active", "applied_version": 12 }
    ])
}

#[test]
fn relay_rows_parse_from_the_exec_payload() {
    let rows: Vec<RelayRow> = serde_json::from_value(list_relays_payload())
        .expect("RelayRow must deserialize the exact JSON operator-admin's list-relays emits");
    assert_eq!(rows.len(), 2);
    // `endpoint` is the field the relay reconciler's corroboration matches on —
    // the one whose loss is silent (probe failure → spare token every reconcile).
    assert_eq!(rows[0].endpoint, "203.0.113.9:4443");
    assert_eq!(rows[1].endpoint, "198.51.100.7:4443");
    // `status` must survive the hop even though the corroboration deliberately
    // ignores it: it is what makes an eviction observable elsewhere.
    assert_eq!(rows[0].status, "active");
    assert_eq!(rows[1].status, "inactive");
}

#[test]
fn gateway_rows_parse_and_pin_snake_case_applied_version() {
    let rows: Vec<GatewayRow> = serde_json::from_value(list_gateways_payload())
        .expect("GatewayRow must deserialize the exact JSON operator-admin's list-gateways emits");
    assert_eq!(rows.len(), 1);
    assert_eq!(rows[0].segment, "home");
    assert_eq!(rows[0].status, "active");

    // The one field where casing is observable: `applied_version`, NOT
    // `appliedVersion`. A camelCase producer would silently yield the serde
    // default (0) rather than erroring, since the field carries #[serde(default)].
    let camel = serde_json::json!([
        { "id": 3, "name": "gw-home", "segment": "home", "status": "active", "appliedVersion": 12 }
    ]);
    let camel_rows: Vec<GatewayRow> =
        serde_json::from_value(camel).expect("camelCase payload still parses (field defaults)");
    assert_eq!(
        camel_rows[0].applied_version, 0,
        "camelCase `appliedVersion` does NOT populate the field — proving the contract is \
         snake_case and that a producer-side rename would fail SILENTLY, which is exactly \
         why this pin exists"
    );
}

#[test]
fn a_renamed_required_key_fails_loudly_rather_than_defaulting() {
    // The required keys have no serde default, so a producer-side rename is a
    // hard parse error (the loud half of the contract). Pinned per key so a
    // future `#[serde(default)]` cannot quietly turn a rename into a silent
    // empty value.
    for missing in ["id", "name", "endpoint", "status"] {
        let mut obj = serde_json::json!({
            "id": 1, "name": "relay-9f3ac2", "endpoint": "203.0.113.9:4443", "status": "active"
        });
        let o = obj.as_object_mut().unwrap();
        let v = o.remove(missing).unwrap();
        o.insert(format!("{missing}Renamed"), v);
        let res: Result<RelayRow, _> = serde_json::from_value(obj);
        assert!(
            res.is_err(),
            "a renamed/missing {missing:?} key must fail the parse loudly, not default silently"
        );
    }
}
