use crate::control_plane::backend_api::proto::raptorgate::config::ConfigResponse;
use crate::control_plane::error::SnapshotError;

pub trait SnapshotStore: Send + Sync {
    fn load(&self) -> Result<Option<ConfigResponse>, SnapshotError>;
    fn save(&self, response: &ConfigResponse) -> Result<(), SnapshotError>;
}
