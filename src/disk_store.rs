use std::path::{self, Path, PathBuf};
 
use serde::{Deserialize, Serialize};
use thiserror::Error;
use tokio::{fs::{self}, sync::Mutex};
use uuid::Uuid;
 
#[derive(Debug, Deserialize, Serialize, Clone, PartialEq)]
pub struct SavedProperty<T> {
    pub id: Uuid,
    #[serde(flatten)]
    pub contents: T,
}
 
#[derive(Deserialize, Serialize, Clone)]
struct ListFileLayout<T> {
    items: Vec<SavedProperty<T>>
}
 
struct DiskStore<T> {
    name: PathBuf,
    save_dir: PathBuf,
    marker: std::marker::PhantomData<T>,
    pending: Mutex<()>
}
 
impl<T> DiskStore<T> where T: for<'a> Deserialize<'a> + Serialize + Clone {
    fn new(name: impl AsRef<Path>, save_dir: PathBuf) -> Self {
        Self { name: name.as_ref().to_owned(), marker: std::marker::PhantomData, save_dir, pending: Mutex::new(()) }
    }
 
    async fn load(&self) -> Result<T, StoreError> {
        let _guard = self.pending.lock().await;
        let path = self.save_dir.join(self.name.with_extension("json"));
        let serialized = fs::read_to_string(&path).await?;

        let deserialized = serde_json::from_str::<T>(&serialized)?;
        Ok(deserialized)
    }
 
    //TODO: integrate with git
    async fn save(&self, item: T) -> Result<(), StoreError> {
        let _guard = self.pending.lock().await;

        let serialized = serde_json::to_string_pretty(&item)?;
        let tmp_path = self.save_dir.join(self.name.with_extension("json.tmp"));
        let final_path = self.save_dir.join(self.name.with_extension("json"));

        fs::write(&tmp_path, &serialized).await?;
        // let file = fs::File::open(&tmp_path).await?;
        // file.sync_all().await?;
        fs::rename(&tmp_path, &final_path).await?;
 
        Ok(())
    }
}
 
pub struct ListDiskStore<T> {
    store: DiskStore<ListFileLayout<T>>,
}
 
impl<T> ListDiskStore<T> where T: for<'a> Deserialize<'a> + Serialize + Clone {
    pub fn new(name: impl AsRef<Path>, save_dir: PathBuf) -> Self {
        tracing::debug!("Initializing ListDiskStore with name {:?} in directory {:?}", name.as_ref(), path::absolute(&save_dir));
        Self { store: DiskStore::new(name, save_dir) }
    }
 
    pub async fn load(&self) -> Result<Vec<SavedProperty<T>>, StoreError> {
        Ok(self.store.load().await?.items)
    }
 
    pub async fn save(&self, items: Vec<SavedProperty<T>>) -> Result<(), StoreError> {
        self.store.save(ListFileLayout { items }).await
    }
}
 
pub struct SingleDiskStore<T> {
    store: DiskStore<SavedProperty<T>>,
}
 
impl<T> SingleDiskStore<T> where T: for<'a> Deserialize<'a> + Serialize + Clone {
    pub fn new(name: impl AsRef<Path>, save_dir: PathBuf) -> Self {
        Self { store: DiskStore::new(name, save_dir) }
    }
    pub async fn load(&self) -> Result<SavedProperty<T>, StoreError> {
        self.store.load().await
    }
    pub async fn save(&self, item: SavedProperty<T>) -> Result<(), StoreError> {
        self.store.save(item).await
    }
}
 
#[derive(Debug, Error)]
pub enum StoreError {
    #[error("I/O error: {_0}")]
    Io(#[from] tokio::io::Error),
    #[error("JSON error: {0}")]
    Json(#[from] serde_json::Error),
}
 
 
#[cfg(test)]
mod tests {
    use super::*;
 
    #[derive(Debug, Clone, Deserialize, Serialize, PartialEq, Eq)]
    struct ExampleType {
        name: String,
        port: u16,
        enabled: bool,
    }
 
    fn unique_name(prefix: &str) -> &'static str {
        let name = format!("raptorgate_{prefix}_{}", Uuid::now_v7());
        Box::leak(name.into_boxed_str())
    }
 
    #[tokio::test]
    async fn single_disk_store_roundtrip() -> Result<(), StoreError> {
        let name = unique_name("single");
        let store = SingleDiskStore::<ExampleType>::new(name, PathBuf::from("/tmp"));
 
        let item = SavedProperty {
            id: Uuid::now_v7(),
            contents: ExampleType {
                name: "alpha".to_string(),
                port: 443,
                enabled: true,
            },
        };
 
        store.save(item.clone()).await?;
        let loaded = store.load().await?;
 
        assert_eq!(loaded, item);
 
        let _ = fs::remove_file(format!("/tmp/{name}.json")).await;
        Ok(())
    }
 
    #[tokio::test]
    async fn list_disk_store_roundtrip() -> Result<(), StoreError> {
        let name = unique_name("list");
        let store = ListDiskStore::<ExampleType>::new(name, PathBuf::from("/tmp"));
 
        let items = vec![
            SavedProperty {
                id: Uuid::now_v7(),
                contents: ExampleType {
                    name: "beta".to_string(),
                    port: 53,
                    enabled: true,
                },
            },
            SavedProperty {
                id: Uuid::now_v7(),
                contents: ExampleType {
                    name: "gamma".to_string(),
                    port: 8080,
                    enabled: false,
                },
            },
        ];
 
        store.save(items.clone()).await?;
        let loaded = store.load().await?;
 
        assert_eq!(loaded, items);
 
        let _ = fs::remove_file(format!("/tmp/{name}.json")).await;
        Ok(())
    }
}
