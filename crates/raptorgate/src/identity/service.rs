use std::net::IpAddr;
use std::str::FromStr;
use std::sync::Arc;

use tonic::{Request, Response, Status};

use crate::proto::services::identity_session_service_server::IdentitySessionService;
use crate::proto::services::{
    RevokeIdentitySessionRequest, RevokeIdentitySessionResponse,
    UpsertIdentitySessionRequest, UpsertIdentitySessionResponse,
};

use super::session::{IdentitySession, IdentitySessionParseError};
use super::store::IdentitySessionStore;

#[derive(Clone)]
pub struct IdentitySessionHandler {
    store: Arc<IdentitySessionStore>,
}

impl IdentitySessionHandler {
    pub fn new(store: Arc<IdentitySessionStore>) -> Self {
        Self { store }
    }
}

#[tonic::async_trait]
impl IdentitySessionService for IdentitySessionHandler {
    async fn upsert_identity_session(
        &self,
        request: Request<UpsertIdentitySessionRequest>,
    ) -> Result<Response<UpsertIdentitySessionResponse>, Status> {
        let proto = request
            .into_inner()
            .session
            .ok_or_else(|| Status::invalid_argument(IdentitySessionParseError::MissingSession.to_string()))?;

        let session = IdentitySession::try_from_proto(proto)
            .map_err(|err| Status::invalid_argument(err.to_string()))?;

        let client_ip = session.client_ip;
        let username = session.username.clone();
        let session_id = session.session_id.clone();
        let existed = self.store.upsert(session).is_some();

        tracing::info!(
            event = "identity.session.upsert",
            session_id,
            username,
            client_ip = %client_ip,
            replaced = existed,
            "identity session upserted"
        );

        Ok(Response::new(UpsertIdentitySessionResponse {}))
    }

    async fn revoke_identity_session(
        &self,
        request: Request<RevokeIdentitySessionRequest>,
    ) -> Result<Response<RevokeIdentitySessionResponse>, Status> {
        let inner = request.into_inner();
        let raw_ip = inner.ip_address.trim().to_string();
        if raw_ip.is_empty() {
            return Err(Status::invalid_argument("ip_address is required"));
        }
        let client_ip = IpAddr::from_str(&raw_ip).map_err(|e| {
            Status::invalid_argument(format!("invalid ip_address '{raw_ip}': {e}"))
        })?;

        let outcome = self.store.revoke(&client_ip);
        let removed = outcome.was_removed();

        tracing::info!(
            event = "identity.session.revoke",
            client_ip = %client_ip,
            removed,
            "identity session revoke processed"
        );

        Ok(Response::new(RevokeIdentitySessionResponse { removed }))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::proto::services::IdentityManagerUserSession as ProtoSession;

    fn ts(seconds: i64) -> prost_types::Timestamp {
        prost_types::Timestamp { seconds, nanos: 0 }
    }

    fn sample_proto(ip: &str) -> ProtoSession {
        ProtoSession {
            id: "sess-1".into(),
            identity_user_id: "user-1".into(),
            radius_username: "alice".into(),
            mac_address: "aa:bb:cc:dd:ee:ff".into(),
            ip_address: ip.into(),
            nas_ip: "192.168.20.1".into(),
            called_station_id: "r1".into(),
            authenticated_at: Some(ts(1_700_000_000)),
            expires_at: Some(ts(1_700_003_600)),
            groups: vec!["users".into()],
        }
    }

    #[tokio::test]
    async fn upsert_stores_session() {
        let store = IdentitySessionStore::new_shared();
        let handler = IdentitySessionHandler::new(Arc::clone(&store));
        let _ = handler
            .upsert_identity_session(Request::new(UpsertIdentitySessionRequest {
                session: Some(sample_proto("192.168.20.10")),
            }))
            .await
            .unwrap();

        let ip: IpAddr = "192.168.20.10".parse().unwrap();
        assert!(store.get(&ip).is_some());
    }

    #[tokio::test]
    async fn upsert_rejects_missing_session() {
        let store = IdentitySessionStore::new_shared();
        let handler = IdentitySessionHandler::new(store);
        let err = handler
            .upsert_identity_session(Request::new(UpsertIdentitySessionRequest { session: None }))
            .await
            .unwrap_err();
        assert_eq!(err.code(), tonic::Code::InvalidArgument);
    }

    #[tokio::test]
    async fn upsert_rejects_invalid_ip() {
        let store = IdentitySessionStore::new_shared();
        let handler = IdentitySessionHandler::new(store);
        let err = handler
            .upsert_identity_session(Request::new(UpsertIdentitySessionRequest {
                session: Some(sample_proto("not-an-ip")),
            }))
            .await
            .unwrap_err();
        assert_eq!(err.code(), tonic::Code::InvalidArgument);
    }

    #[tokio::test]
    async fn revoke_returns_removed_true_when_existed() {
        let store = IdentitySessionStore::new_shared();
        let handler = IdentitySessionHandler::new(Arc::clone(&store));
        handler
            .upsert_identity_session(Request::new(UpsertIdentitySessionRequest {
                session: Some(sample_proto("192.168.20.10")),
            }))
            .await
            .unwrap();

        let response = handler
            .revoke_identity_session(Request::new(RevokeIdentitySessionRequest {
                ip_address: "192.168.20.10".into(),
            }))
            .await
            .unwrap()
            .into_inner();
        assert!(response.removed);
        assert!(store.is_empty());
    }

    #[tokio::test]
    async fn revoke_returns_removed_false_when_missing() {
        let store = IdentitySessionStore::new_shared();
        let handler = IdentitySessionHandler::new(store);
        let response = handler
            .revoke_identity_session(Request::new(RevokeIdentitySessionRequest {
                ip_address: "10.10.10.10".into(),
            }))
            .await
            .unwrap()
            .into_inner();
        assert!(!response.removed);
    }

    #[tokio::test]
    async fn revoke_rejects_invalid_ip() {
        let store = IdentitySessionStore::new_shared();
        let handler = IdentitySessionHandler::new(store);
        let err = handler
            .revoke_identity_session(Request::new(RevokeIdentitySessionRequest {
                ip_address: "not-an-ip".into(),
            }))
            .await
            .unwrap_err();
        assert_eq!(err.code(), tonic::Code::InvalidArgument);
    }

    #[tokio::test]
    async fn revoke_rejects_empty_ip() {
        let store = IdentitySessionStore::new_shared();
        let handler = IdentitySessionHandler::new(store);
        let err = handler
            .revoke_identity_session(Request::new(RevokeIdentitySessionRequest {
                ip_address: String::new(),
            }))
            .await
            .unwrap_err();
        assert_eq!(err.code(), tonic::Code::InvalidArgument);
    }
}
