const PROTO_INCLUDE_DIRS: &[&str] = &["proto"];

// Firewall is the gRPC CLIENT for event pushing (dials backend's BackendEventService).
const EVENT_CLIENT_PROTO_FILES: &[&str] = &[
    "proto/events/firewall_events.proto",
    "proto/services/event_service.proto",
];

// Firewall is the gRPC SERVER for queries (backend dials FirewallQueryService).
const QUERY_SERVER_PROTO_FILES: &[&str] = &["proto/services/query_service.proto"];

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

    for file in EVENT_CLIENT_PROTO_FILES
        .iter()
        .chain(QUERY_SERVER_PROTO_FILES)
        .chain(CONTROL_PLANE_PROTO_FILES)
    {
        println!("cargo:rerun-if-changed={file}");
    }
    println!("cargo:rerun-if-changed=proto");

    tonic_prost_build::configure()
        .build_client(true)
        .build_server(false)
        .compile_protos(EVENT_CLIENT_PROTO_FILES, PROTO_INCLUDE_DIRS)?;

    tonic_prost_build::configure()
        .build_client(false)
        .build_server(true)
        .compile_protos(QUERY_SERVER_PROTO_FILES, PROTO_INCLUDE_DIRS)?;

    tonic_prost_build::configure()
        .build_client(true)
        .build_server(true)
        .compile_protos(CONTROL_PLANE_PROTO_FILES, PROTO_INCLUDE_DIRS)?;

    Ok(())
}
