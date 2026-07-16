fn main() -> Result<(), Box<dyn std::error::Error>> {
    tonic_build::configure().build_server(true).build_client(true).compile_protos(
        &["../../proto/wiremesh/v1/enrollment.proto",
          "../../proto/wiremesh/v1/sync.proto",
          "../../proto/wiremesh/v1/admin.proto"],
        &["../../proto"],
    )?;
    Ok(())
}
