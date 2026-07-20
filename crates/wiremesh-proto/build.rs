fn main() -> Result<(), Box<dyn std::error::Error>> {
    tonic_build::configure()
        .build_server(true)
        .build_client(true)
        // 4c Task 1: `RelayInfo` is stored in the gateway's `DesiredState`
        // (`wiremesh-gateway::state::DesiredState.relays`), which derives
        // `serde::Serialize`/`Deserialize` for fail-static `state.json`
        // persistence. Give the generated type the same derives so it can
        // live in that struct without a hand-rolled mirror type.
        .type_attribute("wiremesh.v1.RelayInfo", "#[derive(serde::Serialize, serde::Deserialize)]")
        .compile_protos(
            &["../../proto/wiremesh/v1/enrollment.proto",
              "../../proto/wiremesh/v1/sync.proto",
              "../../proto/wiremesh/v1/admin.proto"],
            &["../../proto"],
        )?;
    Ok(())
}
