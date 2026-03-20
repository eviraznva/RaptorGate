pub mod raptorgate {
    pub mod common {
        tonic::include_proto!("raptorgate.common");
    }
    pub mod config {
        tonic::include_proto!("raptorgate.config");
    }
    pub mod events {
        tonic::include_proto!("raptorgate.events");
    }
    pub mod telemetry {
        tonic::include_proto!("raptorgate.telemetry");
    }
    
    tonic::include_proto!("raptorgate");
}
