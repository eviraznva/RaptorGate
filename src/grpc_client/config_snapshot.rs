use std::sync::Arc;
use prost::Message;
use redb::{Database, ReadableDatabase, TableDefinition};
use crate::grpc_client::proto_types::raptorgate::config::ConfigResponse;

const KEY: u64 = 0;
const TABLE: TableDefinition<u64, &[u8]> = TableDefinition::new("snapshots");

pub struct ConfigSnapshot {
    db: Database,
}

impl ConfigSnapshot {
    pub fn open(path: &str) -> Result<Self, redb::DatabaseError> {
        Ok(Self { db: Database::create(path)? })
    }
    
    pub fn save_bg(self: Arc<Self>, resp: ConfigResponse) {
        tokio::task::spawn_blocking(move || {
            let bytes = resp.encode_to_vec();
            match self.write_bytes(&bytes) {
                Ok(()) => tracing::info!("Snapshot konfiguracji zapisany do Redb"),
                Err(e) => tracing::warn!(error = %e, "Zapis snapshotu do Redb nieudany"),
            }
        });
    }

    fn write_bytes(&self, bytes: &[u8]) -> anyhow::Result<()> {
        let tx = self.db.begin_write()?;
        {
            let mut table = tx.open_table(TABLE)?;
            table.insert(KEY, bytes)?;
        }
        
        tx.commit()?;
        Ok(())
    }
    
    pub fn load(&self) -> Option<ConfigResponse> {
        match self.read_bytes() {
            Ok(Some(bytes)) => match ConfigResponse::decode(bytes.as_slice()) {
                Ok(resp) => {
                    tracing::info!(
                        version = resp.config_version,
                        "Snapshot konfiguracji wczytany z Redb"
                    );
                    Some(resp)
                }
                Err(e) => {
                    tracing::warn!(error = %e, "Deserializacja snapshotu nieudana");
                    None
                }
            },
            Ok(None) => None,
            Err(e) => {
                tracing::warn!(error = %e, "Odczyt snapshotu z Redb nieudany");
                None
            }
        }
    }

    fn read_bytes(&self) -> anyhow::Result<Option<Vec<u8>>> {
        let tx = self.db.begin_read()?;
        
        let table = match tx.open_table(TABLE) {
            Ok(t) => t,
            Err(redb::TableError::TableDoesNotExist(_)) => return Ok(None),
            Err(e) => return Err(e.into()),
        };
        
        Ok(table.get(KEY)?.map(|g| g.value().to_vec()))
    }
}
