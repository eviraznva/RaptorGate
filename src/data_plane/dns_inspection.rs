use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};
use arc_swap::ArcSwap;
use rustc_hash::{FxHashMap, FxHashSet};

use crate::dpi::DpiContext;
use crate::dpi::parsers::dns::DnsRecordType;
use crate::events;
use crate::events::{EchAction, EchOrigin};

// Do debugowania
#[derive(Default, Debug)]
pub struct BlocklistStats {
    pub total_nodes: usize,
    pub terminal_nodes: usize,
    pub wildcard_nodes: usize,
}

/// Struktura reprezentująca węzeł drzewa dla etykiet domeny.
#[derive(Default, Debug)]
struct LabelNode {
    /// Wskazuje, czy ten węzeł jest końcem danej sekwencji etykiet (czyli kompletną domenę).
    is_terminal: bool,
    /// Jest to mapa haszująca przechowująca dzieci, gdzie kluczem jest etykieta domeny,
    /// a wartością kolejny węzeł.
    children: FxHashMap<Box<str>, LabelNode>,
}

/// Struktura reprezentująca drzewo zablokowanych domen,
/// które jest używane do przechowywania i sprawdzania zablokowanych domen.
#[derive(Default, Debug)]
pub struct DomainBlockTree {
    root: LabelNode,
}

impl DomainBlockTree {
    pub fn new() -> Self {
        Self::default()
    }

    /// Wstawia domenę do drzewa.
    /// Obsługuje:
    ///   "google.com"     — blokuje dokładnie google.com
    ///   "*.google.com"   — blokuje wszystkie subdomeny google.com
    ///   "*.com"          — blokuje wszystkie domeny .com
    pub fn insert(&mut self, domain: &str) {
        let (labels, is_wildcard) = Self::parse_domain(domain);

        let mut current_node = &mut self.root;

        for label in &labels {
            current_node = current_node.children.entry((*label).into()).or_default();
        }

        if is_wildcard {
            // Wstawiamy * jako dziecko ostatniego węzła
            current_node.children.entry("*".into()).or_default().is_terminal = true;
        } else {
            current_node.is_terminal = true;
        }
    }

    /// Sprawdzamy czy domena jest zablokowana.
    pub fn is_blocked(&self, domain: &str) -> bool {
        let domain = domain.trim_end_matches('.').to_lowercase();

        let labels: Vec<&str> = domain.split('.').rev().collect();

        let mut current_node = &self.root;

        for label in &labels {
            // Jeżeli znajdziemy * jako dziecko, to oznacza że wszystkie subdomeny są zablokowane
            if current_node.children.get("*").map_or(false, |n| n.is_terminal) {
                return true;
            }

            match current_node.children.get(*label) {
                None => return false, // Brak ścieżki, domena nie zablokowana
                Some(child) => current_node = child,
            }
        }

        // Sprawdzamy, czy końcowy węzeł jest terminalny (czyli dokładnie ta domena jest zablokowana)
        current_node.is_terminal
    }

    // Pozwala ładować wiele domen z tablicy, ignorując puste linie i komentarze (linie zaczynające się od #).
    pub fn load_from_array(&mut self, lines: impl Iterator<Item = impl AsRef<str>>) {
        for line in lines {
            let line = line.as_ref();
            let trimmed = line.trim();

            if trimmed.is_empty() || trimmed.starts_with('#') {
                continue;
            }

            self.insert(trimmed);
        }
    }

    /// Statystyki dla debugowania
    pub fn stats(&self) -> BlocklistStats {
        let mut stats = BlocklistStats::default();

        Self::count_nodes(&self.root, &mut stats);

        stats
    }

    /// Parsuje wpis konfiguracyjny.
    /// Zwraca etykiety od tyłu, a także flagę czy dany wpis posiada *.
    fn parse_domain(entry: &str) -> (Vec<&str>, bool) {
        let is_wildcard = entry.starts_with("*.");

        let domain = if is_wildcard { &entry[2..] } else { entry };

        let labels: Vec<&str> = domain.split('.').rev().collect();

        (labels, is_wildcard)
    }

    /// Wypisuje drzewo w czytelnej strukturze drzewa (do debugowania).
    /// Etykiety są przechowywane od TLD, więc np. `google.com` → `com → google`.
    pub fn print_tree(&self) {
        println!("DomainBlockTree (etykiety od TLD):");

        let mut children: Vec<(&str, &LabelNode)> = self.root.children
            .iter().map(|(k, v)| (k.as_ref(), v))
            .collect();

        children.sort_by_key(|(k, _)| *k);

        for (i, (label, node)) in children.iter().enumerate() {
            Self::print_node(label, node, "", i == children.len() - 1);
        }
    }

    fn print_node(label: &str, node: &LabelNode, prefix: &str, is_last: bool) {
        let connector = if is_last { "└── " } else { "├── " };

        let marker = if label == "*" {
            " [WILDCARD]"
        } else if node.is_terminal {
            " [BLOCKED]"
        } else {
            ""
        };

        println!("{}{}{}{}", prefix, connector, label, marker);

        let child_prefix = format!("{}{}", prefix, if is_last { "    " } else { "│   " });

        let mut children: Vec<(&str, &LabelNode)> = node.children.iter()
            .map(|(k, v)| (k.as_ref(), v)).collect();

        children.sort_by_key(|(k, _)| *k);

        for (i, (child_label, child_node)) in children.iter().enumerate() {
            Self::print_node(child_label, child_node, &child_prefix, i == children.len() - 1);
        }
    }

    // Funkcja pomocnicza do zliczania statystyk drzewa, przydatna do debugowania.
    fn count_nodes(node: &LabelNode, stats: &mut BlocklistStats) {
        stats.total_nodes += 1;

        if node.is_terminal {
            stats.terminal_nodes += 1;
        }

        for (key, child) in &node.children {
            if key.as_ref() == "*" && child.is_terminal {
                stats.wildcard_nodes += 1;
            }

            Self::count_nodes(child, stats);
        }
    }
}

/// Konfiguracja progów detekcji
#[derive(Debug, Clone)]
pub struct TunnelingDetectorConfig {
    /// Maks. długość pojedynczej etykiety subdomeny
    pub max_label_length: usize,
    /// Próg entropii Shannona (bit/znak) — powyżej → podejrzane
    pub entropy_threshold: f32,
    /// Okno czasowe dla liczników
    pub window: Duration,
    /// Maks. zapytań do jednej domeny nadrzędnej w oknie
    pub max_queries_per_domain: usize,
    /// Maks. unikalnych subdomen tej samej domeny nadrzędnej w oknie
    pub max_unique_subdomains: usize,
    /// Próg znormalizowanego score (0.0–1.0) → Alert
    pub alert_threshold: f32,
    /// Próg znormalizowanego score (0.0–1.0) → Block
    pub block_threshold: f32,
}

impl Default for TunnelingDetectorConfig {
    fn default() -> Self {
        Self {
            max_label_length: 40,
            entropy_threshold: 3.5,
            window: Duration::from_secs(60),
            max_queries_per_domain: 100,
            max_unique_subdomains: 20,
            alert_threshold: 0.35,
            block_threshold: 0.5,
        }
    }
}

#[derive(Debug)]
enum TunnelingSignal {
    HighEntropy { label: String, entropy: f32 },
    LongLabel { label: String, length: usize },
    QueryRateExceeded { domain: String, count: usize },
    UniqueSubdomainFlood { domain: String, unique: usize },
    SuspiciousRecordType { qtype: DnsRecordType },
}

// Teoretyczne maksimum, gdy wszystkie sygnały strzelają naraz:
// HighEntropy:          log2(64) * 10 ≈ 60  (base64 = 64 znaki, max entropia)
// LongLabel:            20
// QueryRateExceeded:    40
// UniqueSubdomainFlood: 50
// SuspiciousRecordType: 15
//                      ---
//                      185
const MAX_SCORE: f32 = 185.0;

impl TunnelingSignal {
    fn score(&self) -> u32 {
        match self {
            Self::HighEntropy { entropy, .. }  => (*entropy * 10.0) as u32,
            Self::LongLabel { .. }              => 20,
            Self::QueryRateExceeded { .. }      => 40,
            Self::UniqueSubdomainFlood { .. }   => 50,
            Self::SuspiciousRecordType { .. }   => 15,
        }
    }

    fn describe(&self) -> String {
        match self {
            Self::HighEntropy { label, entropy } =>
                format!("high entropy {entropy:.2} for '{label}'"),
            Self::LongLabel { label, length } =>
                format!("long label ({length} characters): '{label}'"),
            Self::QueryRateExceeded { domain, count } =>
                format!("too many queries ({count}) to '{domain}'"),
            Self::UniqueSubdomainFlood { domain, unique } =>
                format!("too many unique subdomains ({unique}) for '{domain}'"),
            Self::SuspiciousRecordType { qtype } =>
                format!("suspicious record type: {qtype:?}"),
        }
    }
}

#[derive(Debug, Default)]
struct DomainStats {
    queries: Vec<Instant>,
    unique_subdomains: FxHashSet<String>,
}

impl DomainStats {
    fn prune(&mut self, window: Duration) {
        let cutoff = Instant::now() - window;

        self.queries.retain(|t| *t > cutoff);

        if self.queries.is_empty() {
            self.unique_subdomains.clear();
        }
    }
}


#[derive(Debug, Clone, PartialEq)]
pub enum DnsInspectionVerdict {
    Allow,
    Alert(String),
    Block(String),
}

pub struct TunnelingDetector {
    config: TunnelingDetectorConfig,
    stats: FxHashMap<String, DomainStats>,
}

impl TunnelingDetector {
    pub fn new(config: TunnelingDetectorConfig) -> Self {
        Self {
            config,
            stats: FxHashMap::default(),
        }
    }

    /// Analizuje zapytanie DNS i zwraca werdykt.
    /// Znormalizowany score jest w przedziale 0.0–1.0.
    pub fn inspect(&mut self, fqdn: &str, qtype: &DnsRecordType) -> DnsInspectionVerdict {
        let signals = self.collect_signals(fqdn, qtype);

        if signals.is_empty() {
            return DnsInspectionVerdict::Allow;
        }

        let raw_score: u32 = signals.iter().map(|s| s.score()).sum();

        // Clamp do 1.0 — raw_score może przekroczyć MAX_SCORE gdy wiele
        // etykiet ma wysoką entropię jednocześnie (każda dodaje osobny sygnał)
        let normalized = (raw_score as f32 / MAX_SCORE).min(1.0);

        let reason = signals.iter().map(|s| s.describe())
            .collect::<Vec<_>>().join("; ");

        if normalized >= self.config.block_threshold {
            DnsInspectionVerdict::Block(format!(
                "DNS tunneling detected (score={normalized:.2}): {reason}"
            ))
        } else if normalized >= self.config.alert_threshold {
            DnsInspectionVerdict::Alert(format!(
                "DNS tunneling suspected (score={normalized:.2}): {reason}"
            ))
        } else {
            DnsInspectionVerdict::Allow
        }
    }

    fn collect_signals(&mut self, fqdn: &str, qtype: &DnsRecordType) -> Vec<TunnelingSignal> {
        let mut signals = Vec::new();

        let fqdn = fqdn.trim_end_matches('.').to_lowercase();

        let labels: Vec<&str> = fqdn.split('.').collect();

        let parent_domain = Self::extract_parent_domain(&labels);

        let subdomain_labels = if labels.len() > 2 { &labels[..labels.len() - 2] } else { &[] };

        // --- Per-etykieta ---
        for label in subdomain_labels {
            if label.len() > self.config.max_label_length {
                signals.push(TunnelingSignal::LongLabel {
                    label: label.to_string(),
                    length: label.len(),
                });
            }

            let entropy = Self::shannon_entropy(label);

            if entropy > self.config.entropy_threshold {
                signals.push(TunnelingSignal::HighEntropy {
                    label: label.to_string(),
                    entropy,
                });
            }
        }

        // --- Typ rekordu ---
        if Self::is_suspicious_record_type(qtype) {
            signals.push(TunnelingSignal::SuspiciousRecordType {
                qtype: qtype.clone(),
            });
        }

        // --- Statystyki per-domena ---
        let stats = self.stats.entry(parent_domain.clone()).or_default();
        
        stats.prune(self.config.window);
        stats.queries.push(Instant::now());

        if !subdomain_labels.is_empty() {
            stats.unique_subdomains.insert(subdomain_labels.join("."));
        }

        if stats.queries.len() > self.config.max_queries_per_domain {
            signals.push(TunnelingSignal::QueryRateExceeded {
                domain: parent_domain.clone(),
                count: stats.queries.len(),
            });
        }

        if stats.unique_subdomains.len() > self.config.max_unique_subdomains {
            signals.push(TunnelingSignal::UniqueSubdomainFlood {
                domain: parent_domain.clone(),
                unique: stats.unique_subdomains.len(),
            });
        }

        signals
    }

    fn is_suspicious_record_type(qtype: &DnsRecordType) -> bool {
        matches!(qtype, DnsRecordType::Txt | DnsRecordType::Null | DnsRecordType::Mx | DnsRecordType::Https | DnsRecordType::Svcb)
    }

    fn shannon_entropy(s: &str) -> f32 {
        if s.is_empty() {
            return 0.0;
        }

        let mut freq = [0u32; 256];

        for byte in s.bytes() {
            freq[byte as usize] += 1;
        }

        let len = s.len() as f32;

        freq.iter()
            .filter(|&&c| c > 0)
            .map(|&c| {
                let p = c as f32 / len;

                -p * p.log2()
            }).sum()
    }

    fn extract_parent_domain(labels: &[&str]) -> String {
        if labels.len() >= 2 {
            labels[labels.len() - 2..].join(".")
        } else {
            labels.join(".")
        }
    }
}

/// Konfiguracja mitygacji ECH na poziomie DNS.
#[derive(Debug, Clone)]
pub struct EchMitigationConfig {
    pub strip_ech_dns: bool,
    pub log_ech_attempts: bool,
}

impl Default for EchMitigationConfig {
    fn default() -> Self {
        Self { strip_ech_dns: true, log_ech_attempts: true }
    }
}

/// Inspektor DNS — przechowuje listę blokowanych domen i sprawdza payloady UDP.
pub struct DnsInspection {
    blocklist: DomainBlockTree,
    tunneling_detector: Mutex<TunnelingDetector>,
    ech_config: ArcSwap<EchMitigationConfig>,
}

impl DnsInspection {
    pub fn new(blocklist: DomainBlockTree, tunneling_detector_config: TunnelingDetectorConfig, ech_config: EchMitigationConfig) -> Arc<Self> {
        Arc::new(Self {
            blocklist,
            tunneling_detector: Mutex::new(TunnelingDetector::new(tunneling_detector_config)),
            ech_config: ArcSwap::new(Arc::new(ech_config)),
        })
    }

    /// Atomowa podmiana konfiguracji ECH (hot-reload z backendu).
    pub fn reload_ech_config(&self, config: EchMitigationConfig) {
        self.ech_config.store(Arc::new(config));
        tracing::info!("ECH mitigation config reloaded");
    }

    /// Sprawdza kontekst DPI pod kątem zablokowanej domeny DNS.
    /// Najpierw sprawdza blocklist, następnie wykrywanie tunelowania.
    pub fn process(&self, dpi_ctx: &DpiContext) -> DnsInspectionVerdict {
        let (Some(domain), Some(qtype)) = (&dpi_ctx.dns_query_name, &dpi_ctx.dns_query_type) else {
            return DnsInspectionVerdict::Allow;
        };

        if self.blocklist.is_blocked(domain) {
            return DnsInspectionVerdict::Block(format!("Domain '{domain}' is blocked by blocklist"));
        }

        if dpi_ctx.dns_is_response == Some(true) && dpi_ctx.dns_has_ech_hints {
            let cfg = self.ech_config.load();
            let action = if cfg.strip_ech_dns { EchAction::Stripped } else { EchAction::Logged };
            if cfg.log_ech_attempts {
                tracing::info!(domain = %domain, "ECH config detected in DNS response (HTTPS/SVCB record)");
                events::emit(events::Event::new(events::EventKind::EchAttemptDetected {
                    source_ip: None,
                    domain: domain.clone(),
                    origin: EchOrigin::DnsHttpsRecord,
                    action,
                }));
            }
            if cfg.strip_ech_dns {
                return DnsInspectionVerdict::Block(format!("ECH: DNS response for '{domain}' blocked (HTTPS/SVCB record)"));
            }
        }

        self.tunneling_detector.lock().unwrap().inspect(domain, qtype)
    }
}

#[cfg(test)]
mod tunneling_detector_tests {
    use super::*;

    fn detector_sensitive() -> TunnelingDetector {
        TunnelingDetector::new(TunnelingDetectorConfig {
            alert_threshold: 0.05,
            block_threshold: 0.3,
            ..Default::default()
        })
    }

    #[test]
    fn clean_domain_allow() {
        let mut d = detector_sensitive();
        assert_eq!(d.inspect("example.com", &DnsRecordType::A), DnsInspectionVerdict::Allow);
    }

    #[test]
    fn high_entropy_label_triggers_signal() {
        let mut d = detector_sensitive();
        // 16 unikalnych znaków → entropia = log2(16) = 4.0, powyżej progu 3.5
        let verdict = d.inspect("abcdefghijklmnop.example.com", &DnsRecordType::A);
        assert!(matches!(verdict, DnsInspectionVerdict::Alert(_) | DnsInspectionVerdict::Block(_)));
    }

    #[test]
    fn long_label_triggers_signal() {
        let mut d = detector_sensitive();
        let long = "a".repeat(41);
        let fqdn = format!("{long}.example.com");
        let verdict = d.inspect(&fqdn, &DnsRecordType::A);
        assert!(matches!(verdict, DnsInspectionVerdict::Alert(_) | DnsInspectionVerdict::Block(_)));
    }

    #[test]
    fn suspicious_record_type_txt() {
        let mut d = detector_sensitive();
        let verdict = d.inspect("sub.example.com", &DnsRecordType::Txt);
        assert!(matches!(verdict, DnsInspectionVerdict::Alert(_) | DnsInspectionVerdict::Block(_)));
    }

    #[test]
    fn suspicious_record_type_null() {
        let mut d = detector_sensitive();
        let verdict = d.inspect("sub.example.com", &DnsRecordType::Null);
        assert!(matches!(verdict, DnsInspectionVerdict::Alert(_) | DnsInspectionVerdict::Block(_)));
    }

    #[test]
    fn suspicious_record_type_mx() {
        let mut d = detector_sensitive();
        let verdict = d.inspect("sub.example.com", &DnsRecordType::Mx);
        assert!(matches!(verdict, DnsInspectionVerdict::Alert(_) | DnsInspectionVerdict::Block(_)));
    }

    #[test]
    fn safe_record_types_no_signal() {
        let mut d = detector_sensitive();
        assert_eq!(d.inspect("example.com", &DnsRecordType::A),    DnsInspectionVerdict::Allow);
        assert_eq!(d.inspect("example.com", &DnsRecordType::Aaaa), DnsInspectionVerdict::Allow);
        assert_eq!(d.inspect("example.com", &DnsRecordType::Cname), DnsInspectionVerdict::Allow);
    }

    #[test]
    fn query_rate_exceeded_triggers_signal() {
        let mut d = TunnelingDetector::new(TunnelingDetectorConfig {
            max_queries_per_domain: 3,
            alert_threshold: 0.1,
            block_threshold: 0.9,
            ..Default::default()
        });
        for _ in 0..5 {
            d.inspect("sub.example.com", &DnsRecordType::A);
        }
        let verdict = d.inspect("sub.example.com", &DnsRecordType::A);
        assert!(matches!(verdict, DnsInspectionVerdict::Alert(_) | DnsInspectionVerdict::Block(_)));
    }

    #[test]
    fn unique_subdomain_flood_triggers_signal() {
        let mut d = TunnelingDetector::new(TunnelingDetectorConfig {
            max_unique_subdomains: 3,
            alert_threshold: 0.1,
            block_threshold: 0.9,
            ..Default::default()
        });
        for i in 0..5u32 {
            d.inspect(&format!("sub{i}.example.com"), &DnsRecordType::A);
        }
        let verdict = d.inspect("sub99.example.com", &DnsRecordType::A);
        assert!(matches!(verdict, DnsInspectionVerdict::Alert(_) | DnsInspectionVerdict::Block(_)));
    }

    #[test]
    fn block_threshold_returns_block() {
        let mut d = TunnelingDetector::new(TunnelingDetectorConfig {
            block_threshold: 0.0,
            alert_threshold: 0.0,
            ..Default::default()
        });
        let verdict = d.inspect("sub.example.com", &DnsRecordType::Txt);
        assert!(matches!(verdict, DnsInspectionVerdict::Block(_)));
    }

    #[test]
    fn fqdn_trailing_dot_handled() {
        let mut d = detector_sensitive();
        assert_eq!(d.inspect("example.com.", &DnsRecordType::A), DnsInspectionVerdict::Allow);
    }

    #[test]
    fn fqdn_case_insensitive() {
        let mut d = detector_sensitive();
        assert_eq!(d.inspect("EXAMPLE.COM", &DnsRecordType::A), DnsInspectionVerdict::Allow);
    }
}

#[cfg(test)]
mod dns_inspection_process_tests {
    use super::*;
    use crate::dpi::DpiContext;
    use crate::dpi::AppProto;

    fn make_inspection() -> std::sync::Arc<DnsInspection> {
        let mut bl = DomainBlockTree::new();
        bl.insert("blocked.com");
        DnsInspection::new(bl, TunnelingDetectorConfig {
            alert_threshold: 0.1,
            block_threshold: 0.3,
            ..Default::default()
        }, EchMitigationConfig::default())
    }

    fn ctx(name: Option<&str>, qtype: Option<DnsRecordType>) -> DpiContext {
        DpiContext {
            app_proto: Some(AppProto::Dns),
            dns_query_name: name.map(str::to_string),
            dns_query_type: qtype,
            ..Default::default()
        }
    }

    #[test]
    fn no_query_name_allow() {
        let ins = make_inspection();
        assert_eq!(ins.process(&ctx(None, Some(DnsRecordType::A))), DnsInspectionVerdict::Allow);
    }

    #[test]
    fn no_query_type_allow() {
        let ins = make_inspection();
        assert_eq!(ins.process(&ctx(Some("example.com"), None)), DnsInspectionVerdict::Allow);
    }

    #[test]
    fn blocklisted_domain_returns_block() {
        let ins = make_inspection();
        let verdict = ins.process(&ctx(Some("blocked.com"), Some(DnsRecordType::A)));
        assert!(matches!(verdict, DnsInspectionVerdict::Block(_)));
    }

    #[test]
    fn clean_domain_a_record_allow() {
        let ins = make_inspection();
        assert_eq!(
            ins.process(&ctx(Some("example.com"), Some(DnsRecordType::A))),
            DnsInspectionVerdict::Allow
        );
    }

    #[test]
    fn blocklist_takes_priority_over_tunneling() {
        // blocked.com na blocklist — powinno zwrócić Block zanim dojdzie do TunnelingDetector
        let ins = make_inspection();
        let verdict = ins.process(&ctx(Some("blocked.com"), Some(DnsRecordType::Txt)));
        assert!(matches!(verdict, DnsInspectionVerdict::Block(msg) if msg.contains("blocklist")));
    }

    #[test]
    fn tunneling_signal_on_suspicious_subdomain() {
        let ins = make_inspection();
        let verdict = ins.process(&ctx(Some("abcdefghijklmnop.example.com"), Some(DnsRecordType::Txt)));
        assert!(matches!(verdict, DnsInspectionVerdict::Alert(_) | DnsInspectionVerdict::Block(_)));
    }

    fn ech_response_ctx(name: &str) -> DpiContext {
        DpiContext {
            app_proto: Some(AppProto::Dns),
            dns_query_name: Some(name.to_string()),
            dns_query_type: Some(DnsRecordType::Https),
            dns_is_response: Some(true),
            dns_answer_count: 1,
            dns_answer_types: vec![DnsRecordType::Https],
            dns_has_ech_hints: true,
            ..Default::default()
        }
    }

    #[test]
    fn ech_dns_response_blocked_by_default() {
        let ins = make_inspection();
        let verdict = ins.process(&ech_response_ctx("example.com"));
        assert!(matches!(verdict, DnsInspectionVerdict::Block(msg) if msg.contains("ECH")));
    }

    #[test]
    fn ech_dns_response_allowed_when_disabled() {
        let mut bl = DomainBlockTree::new();
        bl.insert("blocked.com");
        let ins = DnsInspection::new(bl, TunnelingDetectorConfig::default(), EchMitigationConfig { strip_ech_dns: false, log_ech_attempts: false });
        let verdict = ins.process(&ech_response_ctx("example.com"));
        assert_eq!(verdict, DnsInspectionVerdict::Allow);
    }

    #[test]
    fn ech_dns_query_not_blocked() {
        let ins = make_inspection();
        let query_ctx = DpiContext {
            app_proto: Some(AppProto::Dns),
            dns_query_name: Some("example.com".to_string()),
            dns_query_type: Some(DnsRecordType::Https),
            dns_is_response: Some(false),
            dns_has_ech_hints: false,
            ..Default::default()
        };
        assert_eq!(ins.process(&query_ctx), DnsInspectionVerdict::Allow);
    }

    #[test]
    fn blocklist_priority_over_ech() {
        let ins = make_inspection();
        let ech_ctx = DpiContext {
            app_proto: Some(AppProto::Dns),
            dns_query_name: Some("blocked.com".to_string()),
            dns_query_type: Some(DnsRecordType::Https),
            dns_is_response: Some(true),
            dns_answer_count: 1,
            dns_answer_types: vec![DnsRecordType::Https],
            dns_has_ech_hints: true,
            ..Default::default()
        };
        let verdict = ins.process(&ech_ctx);
        assert!(matches!(verdict, DnsInspectionVerdict::Block(msg) if msg.contains("blocklist")));
    }

    #[test]
    fn ech_config_reload() {
        let ins = make_inspection();
        assert!(matches!(ins.process(&ech_response_ctx("example.com")), DnsInspectionVerdict::Block(_)));
        ins.reload_ech_config(EchMitigationConfig { strip_ech_dns: false, log_ech_attempts: false });
        assert_eq!(ins.process(&ech_response_ctx("example.com")), DnsInspectionVerdict::Allow);
    }
}

#[cfg(test)]
mod dns_inspection_tests {
    use super::*;

    fn blocklist() -> DomainBlockTree {
        let mut bl = DomainBlockTree::new();
        
        bl.insert("google.com");       // exact
        bl.insert("*.ads.google.com"); // wildcard subdomeny
        bl.insert("*.malware.net");    // wildcard TLD-level
        bl.insert("evil.org");         // exact
        
        bl
    }

    #[test]
    fn exact_match() {
        let bl = blocklist();
        
        assert!(bl.is_blocked("google.com"));
        assert!(bl.is_blocked("evil.org"));
    }

    #[test]
    fn exact_does_not_match_subdomain() {
        let bl = blocklist();
        // google.com jest zablokowane, ale NIE jego subdomeny
        // (chyba że dodasz *.google.com osobno)
        
        assert!(!bl.is_blocked("mail.google.com"));
        assert!(!bl.is_blocked("www.google.com"));
    }

    #[test]
    fn wildcard_blocks_subdomains() {
        let bl = blocklist();
        
        assert!(bl.is_blocked("tracking.ads.google.com"));
        assert!(bl.is_blocked("px.ads.google.com"));
        // ale nie parent sam w sobie
        assert!(!bl.is_blocked("ads.google.com"));
    }

    #[test]
    fn wildcard_deep() {
        let bl = blocklist();
        
        // *.malware.net blokuje DOWOLNĄ głębokość (rekurencyjnie)
        assert!(bl.is_blocked("c2.malware.net"));
        assert!(bl.is_blocked("deep.sub.malware.net"));
    }

    #[test]
    fn unrelated_domains() {
        let bl = blocklist();
        
        assert!(!bl.is_blocked("cloudflare.com"));
        assert!(!bl.is_blocked("example.org"));
    }

    #[test]
    fn case_insensitive() {
        let bl = blocklist();
        
        assert!(bl.is_blocked("GOOGLE.COM"));
        assert!(bl.is_blocked("Google.Com"));
    }
}