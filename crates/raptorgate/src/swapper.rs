use std::{collections::HashMap, sync::Arc};

use arc_swap::ArcSwap;
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::disk_store::{ListDiskStore, SavedProperty};

pub struct Swapper<K, V> {
    data: ArcSwap<HashMap<K, V>>,
    store: ListDiskStore<V>,
}
impl<K, V> Swapper<K, V> 
where 
    K: Eq + std::hash::Hash + Clone + Into<Uuid> + From<Uuid>,
    V: Clone + for<'a> Deserialize<'a> + Serialize
{
    pub fn new(data: HashMap<K, V>, store: ListDiskStore<V>) -> Self {
        Self {
            data: ArcSwap::new(Arc::new(data)),
            store,
        }
    }

    pub async fn swap(&self, new_items: Vec<(K, V)>) -> anyhow::Result<()> {
        let old_items = self.data.load();

        self.store.save(new_items.iter().cloned().map(|(k, v)| SavedProperty {
            id: k.into(), contents: v 
        }).collect()).await?;

        match self.store.load().await {
            Ok(loaded) => {
                let map = loaded.into_iter().map(|prop| (prop.id.into(), prop.contents)).collect();
                self.data.swap(Arc::new(map));
                Ok(())
            }
            Err(mut err) => {
                tracing::error!(error = %err, "Failed to load after save, rolling back disk state");
                if let Err(rollback_err) = self.store.save(old_items.iter().map(|(k, v)| SavedProperty {
                    id: k.clone().into(), contents: v.clone() 
                }).collect()).await {
                    err = rollback_err;
                }
                
                Err(err.into())
            }
        }
    }
    
    pub fn get_all(&self) -> arc_swap::Guard<Arc<HashMap<K, V>>> {
        self.data.load()
    }
    
    pub fn get(&self, id: &K) -> Option<V> {
        self.data.load().get(id).cloned()
    }
}
