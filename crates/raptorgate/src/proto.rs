pub mod common {
    tonic::include_proto!("raptorgate.common");
}

pub mod config {
    tonic::include_proto!("raptorgate.config");
}

pub mod events {
    tonic::include_proto!("raptorgate.events");
}

pub mod services {
    tonic::include_proto!("raptorgate.services");
}
