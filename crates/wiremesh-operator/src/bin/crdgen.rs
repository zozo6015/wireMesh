//! Emit the five WireMesh CRD manifests as multi-document YAML to stdout.
//! `cargo run -p wiremesh-operator --bin crdgen > deploy/operator/crds/wiremesh-crds.yaml`
fn main() -> anyhow::Result<()> {
    for crd in wiremesh_operator::crd::all_crds() {
        println!("---");
        print!("{}", serde_yaml::to_string(&crd)?);
    }
    Ok(())
}
