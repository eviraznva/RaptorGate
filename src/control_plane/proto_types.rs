pub mod raptorgate {
    pub mod common {
        tonic::include_proto!("raptorgate.common");
    }

    pub mod config {
        tonic::include_proto!("raptorgate.config");
    }

    pub mod lifecycle {
        tonic::include_proto!("raptorgate.lifecycle");
    }

    pub mod status {
        tonic::include_proto!("raptorgate.status");
    }

    pub mod telemetry {
        tonic::include_proto!("raptorgate.telemetry");
    }
}