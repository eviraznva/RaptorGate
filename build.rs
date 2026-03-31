const PROTO_INCLUDE_DIRS: &[&str] = &["proto"];

const ALL_PROTO_FILES: &[&str] = &[
    "proto/events/firewall_events.proto",
    "proto/services/event_service.proto",
    "proto/services/query_service.proto",
    "proto/common/common.proto",
    "proto/config/config_models.proto",
    // "proto/config/config_service.proto",
    "proto/control/validation_service.proto",
];

fn main() -> Result<(), Box<dyn std::error::Error>> {
    unsafe {
        std::env::set_var("PROTOC", protoc_bin_vendored::protoc_bin_path()?);
    }

    for file in ALL_PROTO_FILES {
        println!("cargo:rerun-if-changed={file}");
    }

    println!("cargo:rerun-if-changed=proto");

    tonic_prost_build::configure()
        .build_client(true)
        .build_server(true)
        .compile_protos(ALL_PROTO_FILES, PROTO_INCLUDE_DIRS)?;

    Ok(())
}
