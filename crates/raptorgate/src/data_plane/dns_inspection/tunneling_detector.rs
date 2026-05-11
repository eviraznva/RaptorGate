use std::time::{Duration, Instant};

use rustc_hash::{FxHashMap, FxHashSet};

use crate::dpi::parsers::dns::DnsRecordType;
use crate::data_plane::dns_inspection::domain_block::DomainBlockTree;
use crate::data_plane::dns_inspection::config::DnsInspectionDnsTunnelingConfig;

/// Typ sygnału wskazującego na możliwe tunelowanie DNS.
///
/// Każdy sygnał niesie inne ryzyko, dlatego każdemu przypisana jest waga
/// używana przy obliczaniu znormalizowanego prawdopodobieństwa ryzyka.
#[derive(Debug, Clone, Copy)]
enum TunnelingSignal {
    /// Etykieta subdomeny ma wysoką entropię Shannon — typowe dla zakodowanych danych.
    HighEntropy,
    /// Etykieta subdomeny przekracza maksymalną dozwoloną długość.
    LongLabel,
    /// Liczba zapytań do domeny przekroczyła próg w oknie czasowym.
    QueryRateExceeded,
    /// Liczba unikalnych subdomen przekroczyła próg
    UniqueSubdomainFlood,
    /// Typ rekordu DNS (TXT, NULL, MX) typowy dla narzędzi tunelowania.
    SuspiciousRecordType,
}

impl TunnelingSignal {
    /// Zwraca indeks wariantu sygnału używany przy deduplikacji podczas obliczania prawdopodobieństwa.
    fn discriminant(self) -> usize {
        match self {
            TunnelingSignal::HighEntropy          => 0,
            TunnelingSignal::LongLabel            => 1,
            TunnelingSignal::QueryRateExceeded    => 2,
            TunnelingSignal::UniqueSubdomainFlood => 3,
            TunnelingSignal::SuspiciousRecordType => 4,
        }
    }

    /// Waga sygnału przy obliczaniu znormalizowanego prawdopodobieństwa (0.0–1.0).
    fn weight(self) -> f32 {
        match self {
            TunnelingSignal::HighEntropy          => 0.25,
            TunnelingSignal::LongLabel            => 0.20,
            TunnelingSignal::QueryRateExceeded    => 0.30,
            TunnelingSignal::UniqueSubdomainFlood => 0.30,
            TunnelingSignal::SuspiciousRecordType => 0.20,
        }
    }
}

/// Statystyki zapytań dla pojedynczej domeny nadrzędnej.
///
/// Przechowuje znaczniki czasowe zapytań w bieżącym oknie czasowym
/// oraz zbiór unikalnych subdomen widzianych w tym oknie.
#[derive(Debug, Default)]
struct DomainStats {
    /// Znaczniki czasowe zapytań w oknie czasowym.
    queries: Vec<Instant>,
    /// Unikalne subdomeny zaobserwowane w oknie czasowym.
    unique_subdomains: FxHashSet<String>,
}

impl DomainStats {
    /// Usuwa wpisy starsze niż podane okno czasowe.
    /// Jeśli okno nie zawiera żadnych zapytań, czyści też subdomeny.
    fn prune(&mut self, window: Duration) {
        let cutoff = Instant::now() - window;
        self.queries.retain(|t| *t > cutoff);
        
        if self.queries.is_empty() {
            self.unique_subdomains.clear();
        }
    }
}

/// Werdykt inspekcji DNS
#[derive(Debug, Clone, PartialEq)]
pub enum DnsInspectionVerdict {
    /// Zapytanie jest dozwolone — brak podejrzanych sygnałów.
    Allow,
    /// Zapytanie budzi podejrzenia — wygeneruj alert, ale przepuść ruch.
    Alert(String),
    /// Zapytanie jest zablokowane — zbyt duże ryzyko tunelowania.
    Block(String),
}

/// Detektor tunelowania DNS oparty na heurystyce sygnałów.
///
/// Analizuje zapytania DNS pod kątem wzorców charakterystycznych dla narzędzi
/// tunelowania (np. dnscat2, iodine). Wydaje werdykty Allow/Alert/Block na
/// podstawie znormalizowanego prawdopodobieństwa i skonfigurowanych progów.
pub struct TunnelingDetector {
    /// Aktualna konfiguracja detektora.
    config: DnsInspectionDnsTunnelingConfig,
    /// Statystyki per-domena
    stats: FxHashMap<String, DomainStats>,
    /// Drzewa domen ignorowanych przez detektor — zapytania do tych domen są zawsze dozwolone.
    ignore_list: DomainBlockTree,
}

impl TunnelingDetector {
    /// Tworzy nowy detektor na podstawie podanej konfiguracji.
    pub fn new(config: DnsInspectionDnsTunnelingConfig) -> Self {
        let ignore_list = DomainBlockTree::from_domains(config.ignore_domains.iter());
        
        Self {
            config,
            stats: FxHashMap::default(),
            ignore_list,
        }
    }

    /// Analizuje zapytanie DNS i zwraca werdykt bezpieczeństwa.
    ///
    /// Kolejność sprawdzania:
    /// 1. Jeśli moduł jest wyłączony → Allow
    /// 2. Jeśli domena jest na liście ignorowanych → Allow
    /// 3. Oblicz score ze zebranych sygnałów, porównaj z progami → werdykt
    pub fn inspect(&mut self, fqdn: &str, qtype: &DnsRecordType) -> DnsInspectionVerdict {
        if !self.config.enabled {
            return DnsInspectionVerdict::Allow;
        }

        if self.ignore_list.is_blocked(fqdn) {
            return DnsInspectionVerdict::Allow;
        }

        let signals = self.collect_signals(fqdn, qtype);
        let score = Self::compute_score(&signals);

        if score >= self.config.block_threshold {
            DnsInspectionVerdict::Block(format!(
                "DNS tunneling detected for '{}': score={:.2}",
                fqdn.trim_end_matches('.').to_lowercase(),
                score,
            ))
        } else if score >= self.config.alert_threshold {
            DnsInspectionVerdict::Alert(format!(
                "DNS tunneling alert for '{}': score={:.2}",
                fqdn.trim_end_matches('.').to_lowercase(),
                score,
            ))
        } else {
            DnsInspectionVerdict::Allow
        }
    }

    /// Aktualizuje konfigurację detektora bez resetowania zebranych statystyk.
    ///
    /// Pozwala na hot-swap konfiguracji (zmiana progów, okna czasowego itp.)
    /// bez utraty danych historycznych potrzebnych do detekcji.
    pub fn update_config(&mut self, config: DnsInspectionDnsTunnelingConfig) {
        self.ignore_list = DomainBlockTree::from_domains(config.ignore_domains.iter());
        self.config = config;
    }

    /// Zbiera sygnały tunelowania dla danego zapytania DNS i aktualizuje statystyki domeny.
    fn collect_signals(&mut self, fqdn: &str, qtype: &DnsRecordType) -> Vec<TunnelingSignal> {
        let mut signals = Vec::new();

        let fqdn = fqdn.trim_end_matches('.').to_lowercase();
        let labels: Vec<&str> = fqdn.split('.').collect();
        let parent_domain = Self::extract_parent_domain(&labels);
        let subdomain_labels = if labels.len() > 2 { &labels[..labels.len() - 2] } else { &[] };

        for label in subdomain_labels {
            if label.len() > self.config.max_label_length {
                signals.push(TunnelingSignal::LongLabel);
            }
            if Self::shannon_entropy(label) > self.config.entropy_threshold {
                signals.push(TunnelingSignal::HighEntropy);
            }
        }

        if Self::is_suspicious_record_type(qtype) {
            signals.push(TunnelingSignal::SuspiciousRecordType);
        }

        let stats = self.stats.entry(parent_domain).or_default();
        stats.prune(self.config.window_seconds);
        stats.queries.push(Instant::now());

        if !subdomain_labels.is_empty() {
            stats.unique_subdomains.insert(subdomain_labels.join("."));
        }

        if stats.queries.len() > self.config.max_queries_per_domain {
            signals.push(TunnelingSignal::QueryRateExceeded);
        }
        if stats.unique_subdomains.len() > self.config.max_unique_subdomains {
            signals.push(TunnelingSignal::UniqueSubdomainFlood);
        }

        signals
    }

    /// Oblicza znormalizowane prawdopodobieństwo (0.0–1.0) na podstawie zebranych sygnałów.
    ///
    /// Każdy wariant sygnału jest liczony tylko raz,
    /// co zapobiega wielokrotnemu naliczaniu wagi za ten sam typ sygnału.
    fn compute_score(signals: &[TunnelingSignal]) -> f32 {
        let mut seen = [false; 5];
        let mut total = 0.0_f32;

        for signal in signals {
            let idx = signal.discriminant();
            
            if !seen[idx] {
                seen[idx] = true;
                total += signal.weight();
            }
        }

        total.min(1.0)
    }

    /// Sprawdza czy typ rekordu DNS jest typowy dla narzędzi tunelowania.
    fn is_suspicious_record_type(qtype: &DnsRecordType) -> bool {
        matches!(qtype, DnsRecordType::Txt | DnsRecordType::Null | DnsRecordType::Mx)
    }

    /// Oblicza entropię Shannona (bity na symbol) dla podanego ciągu znaków.
    ///
    /// Wysoka entropia (> próg) wskazuje na losowy lub zakodowany tekst,
    /// charakterystyczny dla danych przesyłanych tunelem DNS.
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
            })
            .sum()
    }

    /// Wyznacza domenę nadrzędną z listy etykiet FQDN.
    fn extract_parent_domain(labels: &[&str]) -> String {
        if labels.len() >= 2 {
            labels[labels.len() - 2..].join(".")
        } else {
            labels.join(".")
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn detector(alert: f32, block: f32) -> TunnelingDetector {
        TunnelingDetector::new(DnsInspectionDnsTunnelingConfig {
            enabled: true,
            alert_threshold: alert,
            block_threshold: block,
            ..Default::default()
        })
    }

    #[test]
    fn clean_domain_allow() {
        let mut d = detector(0.6, 0.85);
        assert_eq!(d.inspect("example.com", &DnsRecordType::A), DnsInspectionVerdict::Allow);
    }

    #[test]
    fn disabled_always_allow() {
        let mut d = TunnelingDetector::new(DnsInspectionDnsTunnelingConfig {
            enabled: false,
            ..Default::default()
        });
        assert_eq!(
            d.inspect("abcdefghijklmnopqrstuvwxyz01234567890.evil.com", &DnsRecordType::Txt),
            DnsInspectionVerdict::Allow,
        );
    }

    #[test]
    fn ignore_domain_skips_detection() {
        let mut d = TunnelingDetector::new(DnsInspectionDnsTunnelingConfig {
            enabled: true,
            ignore_domains: vec!["*.safe.com".into()],
            alert_threshold: 0.1,
            block_threshold: 0.1,
            ..Default::default()
        });
        // Nawet z podejrzaną subdomeną, domena jest ignorowana
        let fqdn = format!("{}.safe.com", "x".repeat(50));
        assert_eq!(d.inspect(&fqdn, &DnsRecordType::Txt), DnsInspectionVerdict::Allow);
    }

    #[test]
    fn ignore_wildcard_skips_subdomain() {
        let mut d = TunnelingDetector::new(DnsInspectionDnsTunnelingConfig {
            enabled: true,
            ignore_domains: vec!["*.safe.com".into()],
            alert_threshold: 0.1,
            block_threshold: 0.1,
            ..Default::default()
        });
        let fqdn = format!("{}.sub.safe.com", "x".repeat(50));
        assert_eq!(d.inspect(&fqdn, &DnsRecordType::Txt), DnsInspectionVerdict::Allow);
    }

    #[test]
    fn block_threshold_exceeded() {
        let mut d = TunnelingDetector::new(DnsInspectionDnsTunnelingConfig {
            enabled: true,
            max_label_length: 5,     // LongLabel dla dłuższych
            entropy_threshold: 0.5,  // HighEntropy dla prawie wszystkiego
            max_queries_per_domain: 1,
            alert_threshold: 0.3,
            block_threshold: 0.5,
            ..Default::default()
        });
        // Pierwsze zapytanie — zbieramy QueryRateExceeded dopiero przy kolejnym
        d.inspect("abcdefghij.evil.com", &DnsRecordType::Txt);
        // Drugie zapytanie — QueryRateExceeded aktywne + HighEntropy + LongLabel + SuspiciousRecordType
        let verdict = d.inspect("abcdefghij.evil.com", &DnsRecordType::Txt);
        assert!(
            matches!(verdict, DnsInspectionVerdict::Block(_)),
            "oczekiwano Block, otrzymano: {verdict:?}",
        );
    }

    #[test]
    fn alert_threshold_exceeded_not_block() {
        let mut d = TunnelingDetector::new(DnsInspectionDnsTunnelingConfig {
            enabled: true,
            entropy_threshold: 0.5,  // HighEntropy aktywne (waga 0.25)
            alert_threshold: 0.2,
            block_threshold: 0.9,    // Block bardzo trudny do osiągnięcia
            ..Default::default()
        });
        let verdict = d.inspect("abcdefghijklmno.example.com", &DnsRecordType::A);
        assert!(
            matches!(verdict, DnsInspectionVerdict::Alert(_)),
            "oczekiwano Alert, otrzymano: {verdict:?}",
        );
    }

    #[test]
    fn update_config_preserves_stats() {
        let mut d = TunnelingDetector::new(DnsInspectionDnsTunnelingConfig {
            enabled: true,
            max_queries_per_domain: 2,
            alert_threshold: 0.6,
            block_threshold: 0.85,
            ..Default::default()
        });
        // Załaduj statystyki przez zapytania
        d.inspect("sub.example.com", &DnsRecordType::A);
        d.inspect("sub.example.com", &DnsRecordType::A);

        // Zmień tylko progi — statystyki muszą przetrwać
        d.update_config(DnsInspectionDnsTunnelingConfig {
            enabled: true,
            max_queries_per_domain: 2,
            alert_threshold: 0.1,  // obniżony próg alertu
            block_threshold: 0.85,
            ..Default::default()
        });

        // Trzecie zapytanie — QueryRateExceeded aktywne (stats zachowane)
        let verdict = d.inspect("sub.example.com", &DnsRecordType::A);
        assert!(
            matches!(verdict, DnsInspectionVerdict::Alert(_) | DnsInspectionVerdict::Block(_)),
            "stats powinny być zachowane po update_config: {verdict:?}",
        );
    }

    #[test]
    fn fqdn_trailing_dot_handled() {
        let mut d = detector(0.6, 0.85);
        assert_eq!(d.inspect("example.com.", &DnsRecordType::A), DnsInspectionVerdict::Allow);
    }

    #[test]
    fn fqdn_case_insensitive() {
        let mut d = detector(0.6, 0.85);
        assert_eq!(d.inspect("EXAMPLE.COM", &DnsRecordType::A), DnsInspectionVerdict::Allow);
    }
}
