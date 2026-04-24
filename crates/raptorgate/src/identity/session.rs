use std::net::IpAddr;
use std::str::FromStr;
use std::time::SystemTime;

use thiserror::Error;

use crate::proto::config::IdentityManagerUserSession as ProtoSession;

// Runtime reprezentacja aktywnej sesji identity w firewallu.
// Lookup w hot-path robi sie przez `client_ip`, reszta pol jest kontekstowa
// dla pipeline (Issue 5) i observability (Issue 8).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IdentitySession {
    pub session_id: String,
    pub identity_user_id: String,
    pub username: String,
    pub client_ip: IpAddr,
    pub authenticated_at: SystemTime,
    pub expires_at: SystemTime,
    // TODO(Issue 4): tu trafia lista grup z LDAP / VSA po rozwiazaniu mapowania.
    // TODO(Issue 3): sourceIp backend bierze z requestu/polaczenia, nie z body.
}

#[derive(Debug, Error)]
pub enum IdentitySessionParseError {
    #[error("missing session payload")]
    MissingSession,
    #[error("missing ip_address in session")]
    MissingIpAddress,
    #[error("invalid ip_address '{value}': {source}")]
    InvalidIpAddress {
        value: String,
        #[source]
        source: std::net::AddrParseError,
    },
    #[error("missing authenticated_at timestamp")]
    MissingAuthenticatedAt,
    #[error("missing expires_at timestamp")]
    MissingExpiresAt,
    #[error("invalid timestamp: {0}")]
    InvalidTimestamp(&'static str),
    #[error("expires_at ({expires}) is not after authenticated_at ({authenticated})")]
    ExpiresBeforeAuthenticated { authenticated: String, expires: String },
}

impl IdentitySession {
    pub fn try_from_proto(proto: ProtoSession) -> Result<Self, IdentitySessionParseError> {
        if proto.ip_address.trim().is_empty() {
            return Err(IdentitySessionParseError::MissingIpAddress);
        }

        let client_ip = IpAddr::from_str(proto.ip_address.trim()).map_err(|source| {
            IdentitySessionParseError::InvalidIpAddress {
                value: proto.ip_address.clone(),
                source,
            }
        })?;

        let authenticated_at = proto
            .authenticated_at
            .ok_or(IdentitySessionParseError::MissingAuthenticatedAt)
            .and_then(timestamp_to_system_time)?;
        let expires_at = proto
            .expires_at
            .ok_or(IdentitySessionParseError::MissingExpiresAt)
            .and_then(timestamp_to_system_time)?;

        if expires_at <= authenticated_at {
            return Err(IdentitySessionParseError::ExpiresBeforeAuthenticated {
                authenticated: format!("{authenticated_at:?}"),
                expires: format!("{expires_at:?}"),
            });
        }

        Ok(Self {
            session_id: proto.id,
            identity_user_id: proto.identity_user_id,
            username: proto.radius_username,
            client_ip,
            authenticated_at,
            expires_at,
        })
    }

    pub fn is_expired_at(&self, now: SystemTime) -> bool {
        self.expires_at <= now
    }
}

fn timestamp_to_system_time(
    ts: prost_types::Timestamp,
) -> Result<SystemTime, IdentitySessionParseError> {
    if ts.seconds < 0 {
        return Err(IdentitySessionParseError::InvalidTimestamp(
            "seconds must be non-negative",
        ));
    }
    if !(0..1_000_000_000).contains(&ts.nanos) {
        return Err(IdentitySessionParseError::InvalidTimestamp(
            "nanos out of range",
        ));
    }
    let secs = u64::try_from(ts.seconds)
        .map_err(|_| IdentitySessionParseError::InvalidTimestamp("seconds overflow"))?;
    Ok(SystemTime::UNIX_EPOCH + std::time::Duration::new(secs, ts.nanos as u32))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::{Duration, UNIX_EPOCH};

    fn ts(seconds: i64) -> prost_types::Timestamp {
        prost_types::Timestamp { seconds, nanos: 0 }
    }

    fn sample_proto() -> ProtoSession {
        ProtoSession {
            id: "sess-1".into(),
            identity_user_id: "user-1".into(),
            radius_username: "alice".into(),
            mac_address: "aa:bb:cc:dd:ee:ff".into(),
            ip_address: "192.168.20.10".into(),
            nas_ip: "192.168.20.1".into(),
            called_station_id: "r1".into(),
            authenticated_at: Some(ts(1_700_000_000)),
            expires_at: Some(ts(1_700_003_600)),
        }
    }

    #[test]
    fn parses_valid_ipv4_session() {
        let session = IdentitySession::try_from_proto(sample_proto()).unwrap();
        assert_eq!(session.client_ip, "192.168.20.10".parse::<IpAddr>().unwrap());
        assert_eq!(session.username, "alice");
        assert_eq!(
            session.authenticated_at,
            UNIX_EPOCH + Duration::from_secs(1_700_000_000)
        );
    }

    #[test]
    fn parses_valid_ipv6_session() {
        let mut proto = sample_proto();
        proto.ip_address = "2001:db8::1".into();
        let session = IdentitySession::try_from_proto(proto).unwrap();
        assert_eq!(session.client_ip, "2001:db8::1".parse::<IpAddr>().unwrap());
    }

    #[test]
    fn rejects_empty_ip() {
        let mut proto = sample_proto();
        proto.ip_address = String::new();
        let err = IdentitySession::try_from_proto(proto).unwrap_err();
        assert!(matches!(err, IdentitySessionParseError::MissingIpAddress));
    }

    #[test]
    fn rejects_invalid_ip() {
        let mut proto = sample_proto();
        proto.ip_address = "not-an-ip".into();
        let err = IdentitySession::try_from_proto(proto).unwrap_err();
        assert!(matches!(err, IdentitySessionParseError::InvalidIpAddress { .. }));
    }

    #[test]
    fn rejects_missing_authenticated_at() {
        let mut proto = sample_proto();
        proto.authenticated_at = None;
        let err = IdentitySession::try_from_proto(proto).unwrap_err();
        assert!(matches!(err, IdentitySessionParseError::MissingAuthenticatedAt));
    }

    #[test]
    fn rejects_missing_expires_at() {
        let mut proto = sample_proto();
        proto.expires_at = None;
        let err = IdentitySession::try_from_proto(proto).unwrap_err();
        assert!(matches!(err, IdentitySessionParseError::MissingExpiresAt));
    }

    #[test]
    fn rejects_expires_before_authenticated() {
        let mut proto = sample_proto();
        proto.expires_at = Some(ts(1_699_999_999));
        let err = IdentitySession::try_from_proto(proto).unwrap_err();
        assert!(matches!(
            err,
            IdentitySessionParseError::ExpiresBeforeAuthenticated { .. }
        ));
    }

    #[test]
    fn is_expired_at_respects_expires_field() {
        let session = IdentitySession::try_from_proto(sample_proto()).unwrap();
        let before_expiry = UNIX_EPOCH + Duration::from_secs(1_700_003_599);
        let at_expiry = UNIX_EPOCH + Duration::from_secs(1_700_003_600);
        assert!(!session.is_expired_at(before_expiry));
        assert!(session.is_expired_at(at_expiry));
    }

    #[test]
    fn rejects_negative_timestamp() {
        let mut proto = sample_proto();
        proto.authenticated_at = Some(prost_types::Timestamp {
            seconds: -1,
            nanos: 0,
        });
        let err = IdentitySession::try_from_proto(proto).unwrap_err();
        assert!(matches!(err, IdentitySessionParseError::InvalidTimestamp(_)));
    }
}
