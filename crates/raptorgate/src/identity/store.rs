use std::net::IpAddr;
use std::sync::Arc;

use dashmap::DashMap;

use super::session::IdentitySession;

// Wynik Revoke dla logow i odpowiedzi gRPC.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RevokeOutcome {
    Removed,
    NotFound,
}

impl RevokeOutcome {
    pub fn was_removed(self) -> bool {
        matches!(self, Self::Removed)
    }
}

// Runtime store aktywnych sesji identity.
// Klucz to IP klienta (ADR 0002): jedna aktywna sesja per IP, kolejny upsert
// wypiera poprzednia wartosc. Calosc zyje tylko w pamieci, bez disk store.
#[derive(Debug, Default)]
pub struct IdentitySessionStore {
    sessions: DashMap<IpAddr, IdentitySession>,
}

impl IdentitySessionStore {
    pub fn new() -> Self {
        Self {
            sessions: DashMap::new(),
        }
    }

    pub fn new_shared() -> Arc<Self> {
        Arc::new(Self::new())
    }

    // Nadpisuje sesje pod tym samym client_ip. Idempotentny dla tego samego IP.
    // Zwraca poprzednia wartosc jesli byla.
    pub fn upsert(&self, session: IdentitySession) -> Option<IdentitySession> {
        let key = session.client_ip;
        self.sessions.insert(key, session)
    }

    pub fn revoke(&self, client_ip: &IpAddr) -> RevokeOutcome {
        match self.sessions.remove(client_ip) {
            Some(_) => RevokeOutcome::Removed,
            None => RevokeOutcome::NotFound,
        }
    }

    // Lookup hot-path per pakiet wolany z IdentityLookupStage.
    pub fn get(&self, client_ip: &IpAddr) -> Option<IdentitySession> {
        self.sessions.get(client_ip).map(|entry| entry.clone())
    }

    pub fn len(&self) -> usize {
        self.sessions.len()
    }

    pub fn is_empty(&self) -> bool {
        self.sessions.is_empty()
    }

    // TODO(Issue 8): admin UI pokazuje pelna liste sesji z tego snapshotu.
    pub fn snapshot(&self) -> Vec<IdentitySession> {
        self.sessions
            .iter()
            .map(|entry| entry.value().clone())
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::{Duration, UNIX_EPOCH};

    fn session(ip: &str, username: &str, expires_secs: u64) -> IdentitySession {
        IdentitySession {
            session_id: format!("sess-{username}"),
            identity_user_id: format!("user-{username}"),
            username: username.into(),
            client_ip: ip.parse().unwrap(),
            authenticated_at: UNIX_EPOCH + Duration::from_secs(1_700_000_000),
            expires_at: UNIX_EPOCH + Duration::from_secs(expires_secs),
        }
    }

    #[test]
    fn upsert_inserts_new_session() {
        let store = IdentitySessionStore::new();
        let prev = store.upsert(session("192.168.20.10", "alice", 1_700_003_600));
        assert!(prev.is_none());
        assert_eq!(store.len(), 1);
    }

    #[test]
    fn upsert_is_idempotent_for_same_ip() {
        let store = IdentitySessionStore::new();
        store.upsert(session("192.168.20.10", "alice", 1_700_003_600));
        let prev = store.upsert(session("192.168.20.10", "alice", 1_700_007_200));
        assert_eq!(store.len(), 1);
        assert!(prev.is_some());
        let current = store.get(&"192.168.20.10".parse().unwrap()).unwrap();
        assert_eq!(
            current.expires_at,
            UNIX_EPOCH + Duration::from_secs(1_700_007_200)
        );
    }

    #[test]
    fn upsert_evicts_previous_user_on_same_ip() {
        let store = IdentitySessionStore::new();
        store.upsert(session("192.168.20.10", "alice", 1_700_003_600));
        store.upsert(session("192.168.20.10", "bob", 1_700_007_200));
        let current = store.get(&"192.168.20.10".parse().unwrap()).unwrap();
        assert_eq!(current.username, "bob");
        assert_eq!(store.len(), 1);
    }

    #[test]
    fn revoke_returns_removed_when_session_existed() {
        let store = IdentitySessionStore::new();
        store.upsert(session("192.168.20.10", "alice", 1_700_003_600));
        let outcome = store.revoke(&"192.168.20.10".parse().unwrap());
        assert_eq!(outcome, RevokeOutcome::Removed);
        assert!(outcome.was_removed());
        assert!(store.is_empty());
    }

    #[test]
    fn revoke_returns_not_found_for_unknown_ip() {
        let store = IdentitySessionStore::new();
        let outcome = store.revoke(&"10.10.10.10".parse().unwrap());
        assert_eq!(outcome, RevokeOutcome::NotFound);
        assert!(!outcome.was_removed());
    }

    #[test]
    fn snapshot_returns_all_active_sessions() {
        let store = IdentitySessionStore::new();
        store.upsert(session("192.168.20.10", "alice", 1_700_003_600));
        store.upsert(session("192.168.20.11", "bob", 1_700_003_600));
        let mut usernames: Vec<String> = store
            .snapshot()
            .into_iter()
            .map(|s| s.username)
            .collect();
        usernames.sort();
        assert_eq!(usernames, vec!["alice".to_string(), "bob".to_string()]);
    }
}
