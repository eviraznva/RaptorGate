use std::{collections::HashMap, sync::Arc};

use arc_swap::Guard;

pub trait SwappableProvider<Item, Id> {
    async fn swap_policies(&self, new_policies: Vec<(Id, Item)>) -> Result<(), anyhow::Error>; // should write to disk, thats why its async
    fn get_items(&self) -> Guard<Arc<HashMap<Id, Item>>>;
    fn get_item(&self, Item_id: &Id) -> Option<Item>;
}

pub struct ForeignKey<Id, Provider> where Provider: &SwappableEntities {
    id: Id,

}
