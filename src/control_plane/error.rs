#[derive(Debug, thiserror::Error)]
pub enum SnapshotError {
    #[error("snapshot database error: {0}")]
    Database(#[from] redb::DatabaseError),
    #[error("snapshot transaction error: {0}")]
    Transaction(#[from] redb::TransactionError),
    #[error("snapshot table error: {0}")]
    Table(#[from] redb::TableError),
    #[error("snapshot storage error: {0}")]
    Storage(#[from] redb::StorageError),
    #[error("snapshot commit error: {0}")]
    Commit(#[from] redb::CommitError),
    #[error("snapshot decode error: {0}")]
    Decode(#[from] prost::DecodeError),
    #[error("snapshot task join error: {0}")]
    Join(String),
}

#[derive(Debug, thiserror::Error)]
pub enum ControlPlaneError {
    #[error("i/o failed: {0}")]
    Io(#[from] std::io::Error),
    #[error("transport connect failed: {0}")]
    Connect(#[from] tonic::transport::Error),
    #[error("transport serve failed: {0}")]
    Serve(tonic::transport::Error),
    #[error("config fetch failed: {0}")]
    ConfigFetch(#[from] tonic::Status),
    #[error("snapshot error: {0}")]
    Snapshot(#[from] SnapshotError),
    #[error("policy compile failed: {0}")]
    PolicyCompile(String),
    #[error("delta apply failed: {0}")]
    Delta(String),
    #[error("task join failed: {0}")]
    Join(String),
}
