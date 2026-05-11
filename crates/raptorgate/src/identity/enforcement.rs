use std::net::IpAddr;
use std::time::SystemTime;

use super::session::IdentitySession;

// Stan auth doklejany do PacketContext przez IdentityLookupStage.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AuthState {
    Unknown,
    Authenticated,
}

impl std::fmt::Display for AuthState {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let s = match self {
            AuthState::Unknown => "unknown",
            AuthState::Authenticated => "authenticated",
        };
        write!(f, "{s}")
    }
}

// Identity context per pakiet. `original_src_ip` jest zatrzaskiwany przy lookupie,
// zanim NAT postrouting (lub reparse w FTP ALG / TLS decrypted) zmieni adres.
#[derive(Debug, Clone)]
pub struct IdentityContext {
    pub original_src_ip: IpAddr,
    pub auth_state: AuthState,
    pub session: Option<IdentitySession>,
}

impl IdentityContext {
    pub fn unknown(src_ip: IpAddr) -> Self {
        Self {
            original_src_ip: src_ip,
            auth_state: AuthState::Unknown,
            session: None,
        }
    }

    pub fn authenticated(src_ip: IpAddr, session: IdentitySession) -> Self {
        Self {
            original_src_ip: src_ip,
            auth_state: AuthState::Authenticated,
            session: Some(session),
        }
    }

    pub fn is_authenticated(&self) -> bool {
        matches!(self.auth_state, AuthState::Authenticated)
    }
}

// Wybiera identity dla pakietu na podstawie store i czasu arrival.
// Sesje wygasle (expires_at <= now) traktujemy jak brak sesji (ADR 0003).
pub fn resolve_identity(
    store: &super::store::IdentitySessionStore,
    src_ip: IpAddr,
    now: SystemTime,
) -> IdentityContext {
    match store.get(&src_ip) {
        Some(session) if !session.is_expired_at(now) => {
            IdentityContext::authenticated(src_ip, session)
        }
        _ => IdentityContext::unknown(src_ip),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::{Duration, UNIX_EPOCH};

    fn session(ip: &str, expires_secs: u64) -> IdentitySession {
        IdentitySession {
            session_id: "sess-1".into(),
            identity_user_id: "user-1".into(),
            username: "alice".into(),
            client_ip: ip.parse().unwrap(),
            authenticated_at: UNIX_EPOCH + Duration::from_secs(1_700_000_000),
            expires_at: UNIX_EPOCH + Duration::from_secs(expires_secs),
            groups: Vec::new(),
        }
    }

    #[test]
    fn resolve_identity_returns_authenticated_for_active_session() {
        let store = crate::identity::IdentitySessionStore::new();
        store.upsert(session("192.168.10.10", 1_700_003_600));
        let now = UNIX_EPOCH + Duration::from_secs(1_700_000_500);
        let ctx = resolve_identity(&store, "192.168.10.10".parse().unwrap(), now);
        assert!(ctx.is_authenticated());
        assert_eq!(ctx.session.as_ref().unwrap().username, "alice");
    }

    #[test]
    fn resolve_identity_returns_unknown_for_expired_session() {
        let store = crate::identity::IdentitySessionStore::new();
        store.upsert(session("192.168.10.10", 1_700_003_600));
        let now = UNIX_EPOCH + Duration::from_secs(1_700_003_600);
        let ctx = resolve_identity(&store, "192.168.10.10".parse().unwrap(), now);
        assert_eq!(ctx.auth_state, AuthState::Unknown);
        assert!(ctx.session.is_none());
    }

    #[test]
    fn resolve_identity_returns_unknown_for_missing_session() {
        let store = crate::identity::IdentitySessionStore::new();
        let now = UNIX_EPOCH + Duration::from_secs(1_700_000_500);
        let ctx = resolve_identity(&store, "192.168.10.99".parse().unwrap(), now);
        assert_eq!(ctx.auth_state, AuthState::Unknown);
    }
}
