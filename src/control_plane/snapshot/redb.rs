use prost::Message;
use redb::{Database, ReadableDatabase, TableDefinition};

use crate::control_plane::backend_api::proto::raptorgate::config::ConfigResponse;
use crate::control_plane::error::SnapshotError;
use crate::control_plane::snapshot::store::SnapshotStore;

const KEY: u64 = 0;
const TABLE: TableDefinition<u64, &[u8]> = TableDefinition::new("snapshots");

pub struct RedbSnapshotStore {
    db: Database,
}

impl RedbSnapshotStore {
    pub fn open(path: &str) -> Result<Self, SnapshotError> {
        Ok(Self {
            db: Database::create(path)?,
        })
    }
}

impl SnapshotStore for RedbSnapshotStore {
    fn load(&self) -> Result<Option<ConfigResponse>, SnapshotError> {
        let tx = self.db.begin_read()?;
        let table = match tx.open_table(TABLE) {
            Ok(table) => table,
            Err(redb::TableError::TableDoesNotExist(_)) => return Ok(None),
            Err(err) => return Err(err.into()),
        };

        let bytes = match table.get(KEY)? {
            Some(guard) => guard.value().to_vec(),
            None => return Ok(None),
        };

        match ConfigResponse::decode(bytes.as_slice()) {
            Ok(response) => Ok(Some(response)),
            Err(err) => {
                tracing::warn!(
                    error = %err,
                    "Ignoring incompatible snapshot payload and clearing stored snapshot"
                );
                self.clear()?;
                Ok(None)
            }
        }
    }

    fn save(&self, response: &ConfigResponse) -> Result<(), SnapshotError> {
        let tx = self.db.begin_write()?;

        {
            let mut table = tx.open_table(TABLE)?;
            table.insert(KEY, response.encode_to_vec().as_slice())?;
        }

        tx.commit()?;
        Ok(())
    }
}

impl RedbSnapshotStore {
    fn clear(&self) -> Result<(), SnapshotError> {
        let tx = self.db.begin_write()?;
        {
            let mut table = tx.open_table(TABLE)?;
            let _ = table.remove(KEY)?;
        }
        tx.commit()?;
        Ok(())
    }
}
