use std::pin::Pin;
use std::collections::HashMap;

use crate::grpc_client::event_type::EventType;

type HandlerFuture = Pin<Box<dyn Future<Output = ()> + Send>>;
type RawHandler    = Box<dyn Fn(Vec<u8>) -> HandlerFuture + Send + Sync + 'static>;

pub struct EventDispatcher {
    pub handlers: HashMap<&'static str, RawHandler>,
}

impl EventDispatcher {
    pub fn new() -> Self {
        Self { handlers: HashMap::new() }
    }

    pub fn on<T, F, Fut>(mut self, handler: F) -> Self where
        T: prost::Message + Default + EventType + 'static,
        F: Fn(T) -> Fut + Send + Sync + 'static,
        Fut: Future<Output = ()> + Send + 'static,
    {
        let raw: RawHandler = Box::new(move |bytes: Vec<u8>| {
            match T::decode(bytes.as_slice()) {
                Ok(payload) => Box::pin(handler(payload)) as HandlerFuture,
                Err(e) => {
                    tracing::error!("Failed to decode event payload: {e}");
                    Box::pin(async {}) as HandlerFuture
                }
            }
        });
        
        self.handlers.insert(T::TYPE, raw);
        
        self
    }
}