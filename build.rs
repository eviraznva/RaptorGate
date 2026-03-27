const PROTO_INCLUDE_DIRS: &[&str] = &["proto"];

// Both service protos share the raptorgate.services package so they must be
// compiled together — separate calls would overwrite each other's output file.
const SERVICE_PROTO_FILES: &[&str] = &[
    "proto/events/firewall_events.proto",
    "proto/services/event_service.proto",
    "proto/services/query_service.proto",
];

// Control plane config retrieval — kept until control plane is fully removed.
const CONTROL_PLANE_PROTO_FILES: &[&str] = &[
    "proto/common/common.proto",
    "proto/config/config_models.proto",
    "proto/config/config_service.proto",
    "proto/config/config_grpc_service.proto",
    "proto/control/validation_service.proto",
];

fn main() -> Result<(), Box<dyn std::error::Error>> {
    unsafe {
        std::env::set_var("PROTOC", protoc_bin_vendored::protoc_bin_path()?);
    }

    for file in SERVICE_PROTO_FILES.iter().chain(CONTROL_PLANE_PROTO_FILES) {
        println!("cargo:rerun-if-changed={file}");
    }
    println!("cargo:rerun-if-changed=proto");

    // Build client for BackendEventService (firewall dials backend to push events)
    // and server for FirewallQueryService (backend dials firewall for queries).
    tonic_prost_build::configure()
        .build_client(true)
        .build_server(true)
        .compile_protos(SERVICE_PROTO_FILES, PROTO_INCLUDE_DIRS)?;

    tonic_prost_build::configure()
        .build_client(true)
        .build_server(true)
        .compile_protos(CONTROL_PLANE_PROTO_FILES, PROTO_INCLUDE_DIRS)?;

    Ok(())
}
