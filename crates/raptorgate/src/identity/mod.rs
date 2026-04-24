// Runtime store aktywnych sesji identity oraz gRPC service handler.
// Sesje zyja tylko w pamieci (ADR 0002), klucz = IP klienta.

pub mod session;
pub mod store;
pub mod service;

pub use session::{IdentitySession, IdentitySessionParseError};
pub use store::{IdentitySessionStore, RevokeOutcome};
pub use service::IdentitySessionHandler;
