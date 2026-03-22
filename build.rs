const PROTO_INCLUDE_DIRS: &[&str] = &["proto"];

const CLIENT_PROTO_FILES: &[&str] = &[
    "proto/common/common.proto",
    "proto/config/config_models.proto",
    "proto/config/config_service.proto",
    "proto/events/backend_events.proto",
    "proto/events/firewall_events.proto",
    "proto/telemetry/telemetry_models.proto",
    "proto/raptorgate.proto",
];

fn main() -> Result<(), Box<dyn std::error::Error>> {
    unsafe {
        std::env::set_var("PROTOC", protoc_bin_vendored::protoc_bin_path()?);
    }

    for file in CLIENT_PROTO_FILES {
        println!("cargo:rerun-if-changed={file}");
    }

    println!("cargo:rerun-if-changed=proto");

    tonic_prost_build::configure()
        .build_client(true)
        .build_server(false)
        .compile_protos(CLIENT_PROTO_FILES, PROTO_INCLUDE_DIRS)?;

    Ok(())
}

