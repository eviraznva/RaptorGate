use std::io::{Read, Write};
use std::sync::{Mutex, RwLock};
use std::time::{Duration, Instant, SystemTime};
use std::sync::atomic::{AtomicU16, AtomicU64, Ordering};
use std::net::{IpAddr, SocketAddr, TcpStream, UdpSocket};

use thiserror::Error;
use rustc_hash::FxHashMap;
use anyhow::{Context, Result};

use crate::data_plane::dns_inspection::config::{
    DnsInspectionDnssecConfig, DnsInspectionDnssecResolverConfig,
    DnsInspectionDnssecResolverEndpoint, DnsInspectionDnssecTransport,
};

use crate::dpi::parsers::dns::{DnsRecordType, parse_dns};
use crate::data_plane::dns_inspection::types::DnssecStatus;

/// Interfejs dostawcy walidacji DNSSEC.
///
/// Implementowany przez [`super::dns_inspection::DnsInspection`] i wstrzykiwany
/// do [`crate::policy::policy_evaluator::PolicyEvaluator`], co pozwala na wywoływanie
/// walidacji DNSSEC bezpośrednio z reguł RaptorLang.
///
/// Uwaga: metoda `check_domain` może wykonywać blokujące operacje sieciowe (zapytanie
/// do resolvera DNS) przy braku trafienia w cache. Wywołania w kontekście async powinny
/// być opakowywane przez `tokio::task::spawn_blocking`.
pub trait DnssecProvider: Send + Sync {
    /// Sprawdza status DNSSEC dla podanej domeny.
    fn check_domain(&self, domain: &str, qtype: Option<DnsRecordType>) -> DnssecResult;
}

const DEFAULT_EDNS_UDP_PAYLOAD_SIZE: u16 = 1232;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DnssecResult {
    pub status: DnssecStatus,
    pub from_cache: bool,
    pub resolver_addr: Option<SocketAddr>,
    pub checked_at: SystemTime,
}

impl DnssecResult {
    pub fn not_checked() -> Self {
        Self {
            status: DnssecStatus::NotChecked,
            from_cache: false,
            resolver_addr: None,
            checked_at: SystemTime::now(),
        }
    }
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct DnssecMetricsSnapshot {
    pub lookups: u64,
    pub cache_hits: u64,
    pub timeouts: u64,
    pub errors: u64,
    pub secure: u64,
    pub insecure: u64,
    pub bogus: u64,
}

/// Silnik walidacji DNSSEC.
///
/// Przechowuje konfigurację za pomocą `RwLock`, co umożliwia aktualizację
/// pól (np. progi, cache TTL) bez przebudowania klienta
/// resolvera i utraty cache.
#[derive(Debug)]
pub struct DnssecEngine {
    config: RwLock<DnsInspectionDnssecConfig>,
    cache: Mutex<FxHashMap<DnssecCacheKey, DnssecCacheEntry>>,
    resolver: DnssecResolverClient,
    metrics: DnssecMetrics,
}

impl DnssecEngine {
    /// Tworzy nowy silnik DNSSEC na podstawie podanej konfiguracji.
    pub fn new(config: DnsInspectionDnssecConfig) -> Result<Self> {
        Ok(Self {
            resolver: DnssecResolverClient::new(config.resolver.clone())?,
            cache: Mutex::new(FxHashMap::default()),
            metrics: DnssecMetrics::default(),
            config: RwLock::new(config),
        })
    }

    /// Zwraca klon aktualnej konfiguracji silnika (do porównania przy hot-swapie).
    pub fn config(&self) -> DnsInspectionDnssecConfig {
        self.config.read().unwrap().clone()
    }

    /// Aktualizuje pola konfiguracji bez przebudowania klienta.
    ///
    /// Zachowuje cache DNSSEC — stosowane, gdy adres/port resolvera i ustawienia
    /// cache nie uległy zmianie.
    pub fn update_non_resolver_config(&self, new_config: DnsInspectionDnssecConfig) {
        *self.config.write().unwrap() = new_config;
    }

    pub fn metrics_snapshot(&self) -> DnssecMetricsSnapshot {
        self.metrics.snapshot()
    }

    pub fn check_domain(&self, domain: &str, qtype: Option<DnsRecordType>) -> DnssecResult {
        // Klonujemy konfigurację na starcie, aby zwolnić RwLock przed blokującym
        // wywołaniem sieciowym do resolvera DNS.
        let config = self.config.read().unwrap().clone();

        if !config.enabled {
            tracing::trace!(domain, "dnssec check skipped because module is disabled");
            return DnssecResult::not_checked();
        }

        if config.max_lookups_per_packet == 0 {
            tracing::warn!(domain, "dnssec check skipped because max_lookups_per_packet is set to 0");
            return DnssecResult::not_checked();
        }

        let normalized_domain = match normalize_domain(domain) {
            Ok(domain) => domain,
            Err(error) => {
                tracing::warn!(domain, error = %error, "dnssec check skipped because domain is invalid");
                let result = DnssecResult {
                    status: DnssecStatus::Error,
                    from_cache: false,
                    resolver_addr: None,
                    checked_at: SystemTime::now(),
                };

                self.metrics.record_result(result.status);
                return result;
            }
        };

        let qtype = qtype.unwrap_or(DnsRecordType::A);

        let cache_key = DnssecCacheKey {
            domain: normalized_domain.clone().into_boxed_str(),
            qtype,
        };

        if let Some(result) = self.lookup_cache(&cache_key, &config) {
            tracing::trace!(domain = normalized_domain, qtype = ?qtype, status = ?result.status, "dnssec cache hit");

            self.metrics.cache_hits.fetch_add(1, Ordering::Relaxed);
            self.metrics.record_result(result.status);

            return result;
        }

        match self.resolver.lookup(&normalized_domain, qtype, &self.metrics) {
            Ok((response, resolver_addr)) => {
                let status = classify_dnssec_response(&response);

                let result = DnssecResult {
                    status,
                    from_cache: false,
                    resolver_addr: Some(resolver_addr),
                    checked_at: SystemTime::now(),
                };

                tracing::debug!(
                    domain = normalized_domain,
                    qtype = ?qtype,
                    resolver = %resolver_addr,
                    status = ?result.status,
                    "dnssec lookup finished"
                );

                self.store_cache(cache_key, &result, &config);
                self.metrics.record_result(result.status);

                result
            }
            Err(error) => {
                let status = match error {
                    DnssecLookupError::Timeout => DnssecStatus::Timeout,
                    DnssecLookupError::Error(_) => DnssecStatus::Error,
                };

                let result = DnssecResult {
                    status,
                    from_cache: false,
                    resolver_addr: None,
                    checked_at: SystemTime::now(),
                };

                tracing::warn!(
                    domain = normalized_domain,
                    qtype = ?qtype,
                    status = ?status,
                    fallback_action = ?config.default_on_resolver_failure,
                    error = %error,
                    "dnssec lookup failed"
                );

                self.store_cache(cache_key, &result, &config);
                self.metrics.record_result(result.status);

                result
            }
        }
    }

    fn lookup_cache(&self, key: &DnssecCacheKey, config: &DnsInspectionDnssecConfig) -> Option<DnssecResult> {
        if !config.cache.enabled {
            return None;
        }

        let now = Instant::now();
        let mut cache = self.cache.lock().unwrap();

        match cache.get(key) {
            Some(entry) if entry.expires_at > now => {
                let mut result = entry.result.clone();
                result.from_cache = true;
                Some(result)
            }
            Some(_) => {
                cache.remove(key);
                None
            }
            None => None,
        }
    }

    fn store_cache(&self, key: DnssecCacheKey, result: &DnssecResult, config: &DnsInspectionDnssecConfig) {
        if !config.cache.enabled {
            return;
        }

        let ttl = match Self::ttl_for_status(result.status, config) {
            Some(ttl) => ttl,
            None => return,
        };

        let now = Instant::now();
        let mut cache = self.cache.lock().unwrap();

        cache.retain(|_, entry| entry.expires_at > now);

        if config.cache.max_entries > 0 && cache.len() >= config.cache.max_entries {
            evict_oldest_entry(&mut cache);
        }

        cache.insert(
            key,
            DnssecCacheEntry {
                result: result.clone(),
                inserted_at: now,
                expires_at: now + ttl,
            },
        );
    }

    fn ttl_for_status(status: DnssecStatus, config: &DnsInspectionDnssecConfig) -> Option<Duration> {
        match status {
            DnssecStatus::Secure => Some(config.cache.ttl_seconds.secure),
            DnssecStatus::Insecure => Some(config.cache.ttl_seconds.insecure),
            DnssecStatus::Bogus => Some(config.cache.ttl_seconds.bogus),
            DnssecStatus::Timeout | DnssecStatus::Error => Some(config.cache.ttl_seconds.failure),
            DnssecStatus::NotChecked => None,
        }
    }
}

#[derive(Debug, Clone, Hash, PartialEq, Eq)]
struct DnssecCacheKey {
    domain: Box<str>,
    qtype: DnsRecordType,
}

#[derive(Debug, Clone)]
struct DnssecCacheEntry {
    result: DnssecResult,
    inserted_at: Instant,
    expires_at: Instant,
}

fn evict_oldest_entry(cache: &mut FxHashMap<DnssecCacheKey, DnssecCacheEntry>) {
    let oldest_key = cache
        .iter()
        .min_by_key(|(_, entry)| entry.inserted_at)
        .map(|(key, _)| key.clone());

    if let Some(key) = oldest_key {
        cache.remove(&key);
    }
}

#[derive(Debug, Default)]
struct DnssecMetrics {
    lookups: AtomicU64,
    cache_hits: AtomicU64,
    timeouts: AtomicU64,
    errors: AtomicU64,
    secure: AtomicU64,
    insecure: AtomicU64,
    bogus: AtomicU64,
}

impl DnssecMetrics {
    fn snapshot(&self) -> DnssecMetricsSnapshot {
        DnssecMetricsSnapshot {
            lookups: self.lookups.load(Ordering::Relaxed),
            cache_hits: self.cache_hits.load(Ordering::Relaxed),
            timeouts: self.timeouts.load(Ordering::Relaxed),
            errors: self.errors.load(Ordering::Relaxed),
            secure: self.secure.load(Ordering::Relaxed),
            insecure: self.insecure.load(Ordering::Relaxed),
            bogus: self.bogus.load(Ordering::Relaxed),
        }
    }

    fn record_result(&self, status: DnssecStatus) {
        match status {
            DnssecStatus::Secure => {
                self.secure.fetch_add(1, Ordering::Relaxed);
            }
            DnssecStatus::Insecure => {
                self.insecure.fetch_add(1, Ordering::Relaxed);
            }
            DnssecStatus::Bogus => {
                self.bogus.fetch_add(1, Ordering::Relaxed);
            }
            DnssecStatus::Timeout => {
                self.timeouts.fetch_add(1, Ordering::Relaxed);
            }
            DnssecStatus::Error => {
                self.errors.fetch_add(1, Ordering::Relaxed);
            }
            DnssecStatus::NotChecked => {}
        }
    }
}

#[derive(Debug)]
struct DnssecResolverClient {
    config: DnsInspectionDnssecResolverConfig,
    resolvers: Vec<SocketAddr>,
    next_query_id: AtomicU16,
}

impl DnssecResolverClient {
    fn new(config: DnsInspectionDnssecResolverConfig) -> Result<Self> {
        let resolvers = resolver_sequence(&config)?;

        Ok(Self {
            config,
            resolvers,
            next_query_id: AtomicU16::new(1),
        })
    }

    fn lookup(
        &self,
        domain: &str,
        qtype: DnsRecordType,
        metrics: &DnssecMetrics,
    ) -> std::result::Result<(Vec<u8>, SocketAddr), DnssecLookupError> {
        let query_id = self.next_query_id.fetch_add(1, Ordering::Relaxed);
        let request = build_dnssec_query(domain, qtype, query_id)?;

        let mut saw_timeout = false;
        let mut last_error = None;

        for resolver in &self.resolvers {
            for attempt in 0..=self.config.retries {
                tracing::trace!(
                    domain,
                    qtype = ?qtype,
                    resolver = %resolver,
                    attempt,
                    transport = ?self.config.transport,
                    "dnssec lookup attempt"
                );

                metrics.lookups.fetch_add(1, Ordering::Relaxed);

                match self.lookup_once(*resolver, &request) {
                    Ok(response) => {
                        validate_response_id(&request, &response)?;
                        return Ok((response, *resolver));
                    }
                    Err(DnssecLookupError::Timeout) => {
                        saw_timeout = true;
                    }
                    Err(error @ DnssecLookupError::Error(_)) => {
                        last_error = Some(error);
                    }
                }
            }
        }

        if saw_timeout {
            Err(DnssecLookupError::Timeout)
        } else {
            Err(last_error.unwrap_or_else(|| DnssecLookupError::Error("dnssec lookup failed".into())))
        }
    }

    fn lookup_once(
        &self,
        resolver: SocketAddr,
        request: &[u8],
    ) -> std::result::Result<Vec<u8>, DnssecLookupError> {
        match self.config.transport {
            DnsInspectionDnssecTransport::Udp => self.lookup_udp(resolver, request),
            DnsInspectionDnssecTransport::Tcp => self.lookup_tcp(resolver, request),
            DnsInspectionDnssecTransport::UdpWithTcpFallback => {
                let response = self.lookup_udp(resolver, request)?;

                if is_truncated_response(&response) {
                    tracing::debug!(resolver = %resolver, "dnssec udp response truncated, retrying over tcp");
                    self.lookup_tcp(resolver, request)
                } else {
                    Ok(response)
                }
            }
        }
    }

    fn lookup_udp(
        &self,
        resolver: SocketAddr,
        request: &[u8],
    ) -> std::result::Result<Vec<u8>, DnssecLookupError> {
        let bind_addr = if resolver.is_ipv4() {
            SocketAddr::from(([0, 0, 0, 0], 0))
        } else {
            SocketAddr::from(([0, 0, 0, 0, 0, 0, 0, 0], 0))
        };

        let socket = UdpSocket::bind(bind_addr)?;

        socket.set_read_timeout(Some(self.config.timeout_ms))?;
        socket.set_write_timeout(Some(self.config.timeout_ms))?;

        socket.connect(resolver)?;
        socket.send(request)?;

        let mut buffer = vec![0u8; 4096];
        let received = socket.recv(&mut buffer).map_err(map_io_error)?;

        buffer.truncate(received);

        Ok(buffer)
    }

    fn lookup_tcp(
        &self,
        resolver: SocketAddr,
        request: &[u8],
    ) -> std::result::Result<Vec<u8>, DnssecLookupError> {
        let mut stream = TcpStream::connect_timeout(&resolver, self.config.timeout_ms).map_err(map_io_error)?;

        stream.set_read_timeout(Some(self.config.timeout_ms))?;
        stream.set_write_timeout(Some(self.config.timeout_ms))?;

        let request_len = u16::try_from(request.len())
            .map_err(|_| DnssecLookupError::Error("dnssec query exceeds tcp frame length".into()))?;

        stream.write_all(&request_len.to_be_bytes())?;
        stream.write_all(request)?;

        let mut length_buffer = [0u8; 2];
        stream.read_exact(&mut length_buffer).map_err(map_io_error)?;

        let response_len = usize::from(u16::from_be_bytes(length_buffer));
        let mut response = vec![0u8; response_len];

        stream.read_exact(&mut response).map_err(map_io_error)?;

        Ok(response)
    }
}

#[derive(Debug, Error)]
enum DnssecLookupError {
    #[error("dnssec resolver timeout")]
    Timeout,
    #[error("{0}")]
    Error(String),
}

impl From<std::io::Error> for DnssecLookupError {
    fn from(error: std::io::Error) -> Self {
        map_io_error(error)
    }
}

impl From<DomainEncodingError> for DnssecLookupError {
    fn from(error: DomainEncodingError) -> Self {
        Self::Error(error.to_string())
    }
}

fn map_io_error(error: std::io::Error) -> DnssecLookupError {
    match error.kind() {
        std::io::ErrorKind::TimedOut | std::io::ErrorKind::WouldBlock => DnssecLookupError::Timeout,
        _ => DnssecLookupError::Error(error.to_string()),
    }
}

fn resolver_sequence(config: &DnsInspectionDnssecResolverConfig) -> Result<Vec<SocketAddr>> {
    let primary = resolver_endpoint_to_socket_addr(&config.primary)
        .context("failed to parse dnssec primary resolver endpoint")?;

    let mut resolvers = vec![primary];

    if let Some(secondary) = &config.secondary {
        let secondary = resolver_endpoint_to_socket_addr(secondary)
            .context("failed to parse dnssec secondary resolver endpoint")?;
        if secondary != primary {
            resolvers.push(secondary);
        }
    }

    Ok(resolvers)
}

fn resolver_endpoint_to_socket_addr(endpoint: &DnsInspectionDnssecResolverEndpoint) -> Result<SocketAddr> {
    let ip: IpAddr = endpoint
        .address
        .parse()
        .with_context(|| format!("'{}' is not a valid IP address", endpoint.address))?;

    Ok(SocketAddr::new(ip, endpoint.port))
}

fn classify_dnssec_response(response: &[u8]) -> DnssecStatus {
    let Some(parsed) = parse_dns(response) else {
        return DnssecStatus::Error;
    };

    if !parsed.is_response {
        return DnssecStatus::Error;
    }

    match parsed.rcode {
        0 | 3 if parsed.authentic_data => DnssecStatus::Secure,
        0 | 3 => DnssecStatus::Insecure,
        2 => DnssecStatus::Bogus,
        _ => DnssecStatus::Error,
    }
}

fn is_truncated_response(response: &[u8]) -> bool {
    simple_dns::Packet::parse(response)
        .map(|packet| packet.has_flags(simple_dns::PacketFlag::TRUNCATION))
        .unwrap_or(false)
}

fn validate_response_id(request: &[u8], response: &[u8]) -> std::result::Result<(), DnssecLookupError> {
    let request_id = request
        .get(..2)
        .ok_or_else(|| DnssecLookupError::Error("dnssec request missing id".into()))?;

    let response_id = response
        .get(..2)
        .ok_or_else(|| DnssecLookupError::Error("dnssec response missing id".into()))?;

    if request_id == response_id {
        Ok(())
    } else {
        Err(DnssecLookupError::Error("dnssec response id mismatch".into()))
    }
}

fn build_dnssec_query(
    domain: &str,
    qtype: DnsRecordType,
    query_id: u16,
) -> std::result::Result<Vec<u8>, DomainEncodingError> {
    let normalized = normalize_domain(domain)?;
    let mut query = Vec::with_capacity(128);

    query.extend_from_slice(&query_id.to_be_bytes());
    query.extend_from_slice(&0x0100u16.to_be_bytes());
    query.extend_from_slice(&1u16.to_be_bytes());
    query.extend_from_slice(&0u16.to_be_bytes());
    query.extend_from_slice(&0u16.to_be_bytes());
    query.extend_from_slice(&1u16.to_be_bytes());

    encode_domain_name(&mut query, &normalized)?;

    query.extend_from_slice(&u16::from(qtype).to_be_bytes());
    query.extend_from_slice(&1u16.to_be_bytes());

    query.push(0);
    query.extend_from_slice(&41u16.to_be_bytes());
    query.extend_from_slice(&DEFAULT_EDNS_UDP_PAYLOAD_SIZE.to_be_bytes());
    query.extend_from_slice(&0x0000_8000u32.to_be_bytes());
    query.extend_from_slice(&0u16.to_be_bytes());

    Ok(query)
}

fn encode_domain_name(
    buffer: &mut Vec<u8>,
    domain: &str,
) -> std::result::Result<(), DomainEncodingError> {
    for label in domain.split('.') {
        let label_bytes = label.as_bytes();
        let label_len = u8::try_from(label_bytes.len()).map_err(|_| DomainEncodingError::LabelTooLong)?;

        if label_len == 0 {
            return Err(DomainEncodingError::EmptyLabel);
        }

        buffer.push(label_len);
        buffer.extend_from_slice(label_bytes);
    }

    buffer.push(0);

    Ok(())
}

fn normalize_domain(domain: &str) -> std::result::Result<String, DomainEncodingError> {
    let domain = domain.trim().trim_end_matches('.').to_lowercase();

    if domain.is_empty() {
        return Err(DomainEncodingError::EmptyName);
    }

    if domain.len() > 253 {
        return Err(DomainEncodingError::NameTooLong);
    }

    for label in domain.split('.') {
        if label.is_empty() {
            return Err(DomainEncodingError::EmptyLabel);
        }
        if label.len() > 63 {
            return Err(DomainEncodingError::LabelTooLong);
        }
        if !label.is_ascii() {
            return Err(DomainEncodingError::NonAsciiLabel);
        }
    }

    Ok(domain)
}

#[derive(Debug, Error)]
enum DomainEncodingError {
    #[error("dns name is empty")]
    EmptyName,
    #[error("dns label is empty")]
    EmptyLabel,
    #[error("dns label exceeds 63 bytes")]
    LabelTooLong,
    #[error("dns name exceeds 253 characters")]
    NameTooLong,
    #[error("dns label must be ascii or punycode")]
    NonAsciiLabel,
}

#[cfg(test)]
mod tests {
    use std::thread;
    use std::sync::Arc;
    use std::net::{TcpListener, UdpSocket};

    use simple_dns::{CLASS, Packet, PacketFlag, Question, TYPE};

    use super::*;
    use crate::data_plane::dns_inspection::config::{
        DnsInspectionDnssecCacheConfig, DnsInspectionDnssecCacheTtlConfig,
        DnsInspectionDnssecTransport,
    };

    #[test]
    fn build_query_sets_opt_and_do_bit() {
        let query = build_dnssec_query("example.com", DnsRecordType::A, 0x1234).unwrap();
        let parsed = parse_dns(&query).unwrap();

        assert!(!parsed.is_response);
        assert_eq!(parsed.query_name.as_deref(), Some("example.com"));
        assert_eq!(parsed.query_type, Some(DnsRecordType::A));
        assert!(parsed.has_opt);
        assert!(parsed.dnssec_ok);
    }

    #[test]
    fn engine_uses_cache_for_repeated_lookup() {
        let response = response_action(ResponseKind::Secure, false, Duration::from_millis(0));
        let (resolver, capture, handle) = spawn_udp_server(vec![response]);

        let engine = DnssecEngine::new(test_dnssec_config(resolver)).unwrap();

        let first = engine.check_domain("example.com", Some(DnsRecordType::A));
        let second = engine.check_domain("example.com", Some(DnsRecordType::A));

        handle.join().unwrap();

        assert_eq!(first.status, DnssecStatus::Secure);
        assert_eq!(second.status, DnssecStatus::Secure);
        assert!(!first.from_cache);
        assert!(second.from_cache);
        assert_eq!(capture.lock().unwrap().len(), 1);

        let metrics = engine.metrics_snapshot();
        assert_eq!(metrics.lookups, 1);
        assert_eq!(metrics.cache_hits, 1);
        assert_eq!(metrics.secure, 2);
    }

    #[test]
    fn engine_returns_timeout_status() {
        let (resolver, _capture, handle) = spawn_udp_server(vec![response_action(
            ResponseKind::Secure,
            true,
            Duration::from_millis(0),
        )]);

        let mut config = test_dnssec_config(resolver);
        config.cache = DnsInspectionDnssecCacheConfig {
            enabled: false,
            ..DnsInspectionDnssecCacheConfig::default()
        };

        let engine = DnssecEngine::new(config).unwrap();
        let result = engine.check_domain("example.com", Some(DnsRecordType::A));
        handle.join().unwrap();

        assert_eq!(result.status, DnssecStatus::Timeout);
        let metrics = engine.metrics_snapshot();
        assert_eq!(metrics.lookups, 1);
        assert_eq!(metrics.timeouts, 1);
    }

    #[test]
    fn resolver_client_falls_back_to_tcp_when_udp_is_truncated() {
        let port_listener = TcpListener::bind(SocketAddr::from(([127, 0, 0, 1], 0))).unwrap();
        let resolver = port_listener.local_addr().unwrap();
        let udp_socket = UdpSocket::bind(resolver).unwrap();
        let udp_capture = Arc::new(Mutex::new(Vec::new()));
        let tcp_capture = Arc::new(Mutex::new(Vec::new()));

        let udp_capture_clone = Arc::clone(&udp_capture);
        let udp_handle = thread::spawn(move || {
            let mut buffer = [0u8; 2048];
            let (len, peer) = udp_socket.recv_from(&mut buffer).unwrap();
            udp_capture_clone.lock().unwrap().push(buffer[..len].to_vec());
            let response = build_response(&buffer[..len], ResponseKind::Truncated);
            udp_socket.send_to(&response, peer).unwrap();
        });

        let tcp_capture_clone = Arc::clone(&tcp_capture);
        let tcp_handle = thread::spawn(move || {
            let (mut stream, _) = port_listener.accept().unwrap();
            let request = read_tcp_frame(&mut stream);
            tcp_capture_clone.lock().unwrap().push(request.clone());
            let response = build_response(&request, ResponseKind::Secure);
            let response_len = u16::try_from(response.len()).unwrap().to_be_bytes();
            stream.write_all(&response_len).unwrap();
            stream.write_all(&response).unwrap();
        });

        let client = DnssecResolverClient::new(test_resolver_config(
            resolver,
            None,
            DnsInspectionDnssecTransport::UdpWithTcpFallback,
            Duration::from_millis(250),
            0,
        ))
        .unwrap();
        let metrics = DnssecMetrics::default();

        let (response, used_resolver) = client.lookup("example.com", DnsRecordType::A, &metrics).unwrap();

        udp_handle.join().unwrap();
        tcp_handle.join().unwrap();

        assert_eq!(used_resolver, resolver);
        assert_eq!(classify_dnssec_response(&response), DnssecStatus::Secure);
        assert_eq!(udp_capture.lock().unwrap().len(), 1);
        assert_eq!(tcp_capture.lock().unwrap().len(), 1);
    }

    #[test]
    fn resolver_client_retries_after_timeout() {
        let actions = vec![
            response_action(ResponseKind::Secure, true, Duration::from_millis(0)),
            response_action(ResponseKind::Secure, false, Duration::from_millis(0)),
        ];
        let (resolver, capture, handle) = spawn_udp_server(actions);

        let client = DnssecResolverClient::new(test_resolver_config(
            resolver,
            None,
            DnsInspectionDnssecTransport::Udp,
            Duration::from_millis(100),
            1,
        ))
        .unwrap();
        let metrics = DnssecMetrics::default();

        let (response, _) = client.lookup("example.com", DnsRecordType::A, &metrics).unwrap();
        handle.join().unwrap();

        assert_eq!(classify_dnssec_response(&response), DnssecStatus::Secure);
        assert_eq!(capture.lock().unwrap().len(), 2);
        assert_eq!(metrics.snapshot().lookups, 2);
    }

    #[test]
    fn resolver_client_fails_over_to_secondary_resolver() {
        let (primary, _primary_capture, primary_handle) = spawn_udp_server(vec![response_action(
            ResponseKind::Secure,
            true,
            Duration::from_millis(0),
        )]);
        let (secondary, secondary_capture, secondary_handle) = spawn_udp_server(vec![response_action(
            ResponseKind::Secure,
            false,
            Duration::from_millis(0),
        )]);

        let client = DnssecResolverClient::new(test_resolver_config(
            primary,
            Some(secondary),
            DnsInspectionDnssecTransport::Udp,
            Duration::from_millis(100),
            0,
        ))
        .unwrap();
        let metrics = DnssecMetrics::default();

        let (response, used_resolver) = client.lookup("example.com", DnsRecordType::A, &metrics).unwrap();

        primary_handle.join().unwrap();
        secondary_handle.join().unwrap();

        assert_eq!(used_resolver, secondary);
        assert_eq!(classify_dnssec_response(&response), DnssecStatus::Secure);
        assert_eq!(secondary_capture.lock().unwrap().len(), 1);
    }

    fn test_dnssec_config(resolver: SocketAddr) -> DnsInspectionDnssecConfig {
        let mut config = DnsInspectionDnssecConfig::default();
        config.enabled = true;
        config.resolver = test_resolver_config(
            resolver,
            None,
            DnsInspectionDnssecTransport::Udp,
            Duration::from_millis(250),
            0,
        );
        config.cache = DnsInspectionDnssecCacheConfig {
            enabled: true,
            max_entries: 4096,
            ttl_seconds: DnsInspectionDnssecCacheTtlConfig::default(),
        };
        config
    }

    fn test_resolver_config(
        primary: SocketAddr,
        secondary: Option<SocketAddr>,
        transport: DnsInspectionDnssecTransport,
        timeout_ms: Duration,
        retries: u8,
    ) -> DnsInspectionDnssecResolverConfig {
        DnsInspectionDnssecResolverConfig {
            primary: DnsInspectionDnssecResolverEndpoint {
                address: primary.ip().to_string(),
                port: primary.port(),
            },
            secondary: secondary.map(|resolver| DnsInspectionDnssecResolverEndpoint {
                address: resolver.ip().to_string(),
                port: resolver.port(),
            }),
            transport,
            timeout_ms,
            retries,
        }
    }

    #[derive(Clone, Copy)]
    enum ResponseKind {
        Secure,
        Truncated,
    }

    #[derive(Clone, Copy)]
    struct UdpResponseAction {
        kind: ResponseKind,
        drop_response: bool,
        delay: Duration,
    }

    fn response_action(kind: ResponseKind, drop_response: bool, delay: Duration) -> UdpResponseAction {
        UdpResponseAction {
            kind,
            drop_response,
            delay,
        }
    }

    fn spawn_udp_server(
        actions: Vec<UdpResponseAction>,
    ) -> (SocketAddr, Arc<Mutex<Vec<Vec<u8>>>>, thread::JoinHandle<()>) {
        let socket = UdpSocket::bind(SocketAddr::from(([127, 0, 0, 1], 0))).unwrap();
        let addr = socket.local_addr().unwrap();
        let capture = Arc::new(Mutex::new(Vec::new()));
        let capture_clone = Arc::clone(&capture);

        let handle = thread::spawn(move || {
            let mut buffer = [0u8; 2048];
            for action in actions {
                let (len, peer) = socket.recv_from(&mut buffer).unwrap();
                let request = buffer[..len].to_vec();
                capture_clone.lock().unwrap().push(request.clone());
                if action.delay > Duration::from_millis(0) {
                    thread::sleep(action.delay);
                }
                if !action.drop_response {
                    let response = build_response(&request, action.kind);
                    socket.send_to(&response, peer).unwrap();
                }
            }
        });

        (addr, capture, handle)
    }

    fn build_response(request: &[u8], kind: ResponseKind) -> Vec<u8> {
        let parsed = parse_dns(request).unwrap();
        let query_id = u16::from_be_bytes([request[0], request[1]]);
        let qname = parsed.query_name.unwrap();
        let qtype = parsed.query_type.unwrap_or(DnsRecordType::A);

        let mut packet = Packet::new_reply(query_id);
        packet.questions.push(Question::new(
            qname.as_str().try_into().unwrap(),
            TYPE::from(u16::from(qtype)).into(),
            CLASS::IN.into(),
            false,
        ));

        match kind {
            ResponseKind::Secure => {
                packet.set_flags(PacketFlag::AUTHENTIC_DATA);
            }
            ResponseKind::Truncated => {
                packet.set_flags(PacketFlag::TRUNCATION);
            }
        }

        packet.build_bytes_vec().unwrap()
    }

    fn read_tcp_frame(stream: &mut TcpStream) -> Vec<u8> {
        let mut length_buffer = [0u8; 2];
        stream.read_exact(&mut length_buffer).unwrap();
        let length = usize::from(u16::from_be_bytes(length_buffer));
        let mut buffer = vec![0u8; length];
        stream.read_exact(&mut buffer).unwrap();
        buffer
    }
}
