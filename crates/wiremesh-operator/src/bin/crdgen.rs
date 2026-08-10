//! Emit the five WireMesh CRD manifests as multi-document YAML to stdout.
//! `cargo run -p wiremesh-operator --bin crdgen > deploy/operator/crds/wiremesh-crds.yaml`
//!
//! The rendering itself lives in `crd::render_crd_yaml()` so that
//! `tests/crd_manifest_freshness.rs` can check the committed bundles against
//! the same code path this binary uses.
fn main() -> anyhow::Result<()> {
    print!("{}", wiremesh_operator::crd::render_crd_yaml()?);
    Ok(())
}
