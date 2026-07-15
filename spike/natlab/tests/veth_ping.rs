use natlab::Lab;

#[test]
fn veth_pair_pings() {
    let mut lab = Lab::new("nlping").unwrap();
    let a = lab.ns("a").unwrap();
    let b = lab.ns("b").unwrap();
    lab.veth((&a, "v0", "10.9.0.1/24"), (&b, "v1", "10.9.0.2/24")).unwrap();
    let out = a.exec(&["ping", "-c", "1", "-W", "2", "10.9.0.2"]).unwrap();
    assert!(out.status.success(), "ping failed: {}", String::from_utf8_lossy(&out.stderr));
}
