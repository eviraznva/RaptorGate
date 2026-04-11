use std::sync::{Arc, Mutex};
use std::sync::atomic::{AtomicBool, Ordering};

use anyhow::Result;
use arc_swap::ArcSwap;

use crate::dpi::parsers::dns::DnsRecordType;
use crate::data_plane::dns_inspection::config::{DnsInspectionConfig, DnsInspectionEchMitigationConfig};
use crate::data_plane::dns_inspection::domain_block::DomainBlockTree;
use crate::data_plane::dns_inspection::dnssec::{DnssecEngine, DnssecProvider, DnssecResult};
use crate::data_plane::dns_inspection::tunneling_detector::{DnsInspectionVerdict, TunnelingDetector};
use crate::events::{self, EchAction, EchOrigin};

/// Werdykt sprawdzenia blocklist DNS.
///
/// Używany wewnętrznie przez [`DnsBlockListStage`][crate::pipeline::wrappers::DnsBlockListStage].
pub enum BlocklistVerdict {
    /// Domena nie jest na liście blokowanych — przepuść ruch.
    Allow,
    /// Domena jest zablokowana — zatrzymaj ruch i zgłoś powód.
    Block(String),
}

/// Werdykt mitygacji ECH na poziomie DNS (odpowiedzi z rekordami HTTPS/SVCB).
pub enum EchMitigationVerdict {
    /// Brak wskazówek ECH lub konfiguracja nie nakazuje blokady — przepuść.
    Allow,
    /// Odpowiedź DNS zawiera wskazówki ECH i polityka wymaga ich zdjęcia.
    Block(String),
}

/// Agregator inspekcji DNS — przechowuje trzy niezależne pod moduły:
/// Blocklist, Detektor tunelowania i Silnik DNSSEC.
///
/// Synchronizacja jest granularna:
/// - `enabled` — `AtomicBool` (~1 ns, bez locka)
/// - `blocklist` — `ArcSwap<DomainBlockTree>` (lock-free epoch load + przeszukanie trie)
/// - `tunneling` — `Mutex<TunnelingDetector>` (krótka sekcja krytyczna: hash + insert statystyk)
/// - `dnssec` — `ArcSwap<Arc<DnssecEngine>>` (lock-free load; wewnętrzny `RwLock<config>` w silniku)
pub struct DnsInspection {
    /// Globalny przełącznik całego modułu inspekcji DNS.
    enabled: AtomicBool,
    /// Drzewo zablokowanych domen — immutable po budowie, podmieniane atomowo przy hot-swapie.
    blocklist: ArcSwap<DomainBlockTree>,
    /// Detektor tunelowania DNS — mutable (przechowuje statystyki per-domena).
    tunneling: Mutex<TunnelingDetector>,
    /// Silnik walidacji DNSSEC — podmieniane atomowo przy zmianie konfiguracji resolvera.
    dnssec: ArcSwap<Arc<DnssecEngine>>,
    /// Polityka mitygacji ECH na poziomie DNS — hot-swap przez ArcSwap.
    ech_mitigation: ArcSwap<DnsInspectionEchMitigationConfig>,
}

impl DnsInspection {
    /// Tworzy nową instancję agregatora inspekcji DNS na podstawie podanej konfiguracji.
    pub fn new(config: DnsInspectionConfig) -> Result<Arc<Self>> {
        let dnssec_engine = Arc::new(DnssecEngine::new(config.dnssec.clone())?);

        Ok(Arc::new(Self {
            enabled: AtomicBool::new(config.general.enabled),
            blocklist: ArcSwap::new(Arc::new(DomainBlockTree::from_config(&config.blocklist))),
            tunneling: Mutex::new(TunnelingDetector::new(config.dns_tunneling)),
            dnssec: ArcSwap::new(Arc::new(dnssec_engine)),
            ech_mitigation: ArcSwap::new(Arc::new(config.ech_mitigation)),
        }))
    }

    /// Sprawdza, czy domena DNS jest na liście blokowanych.
    ///
    /// Odczyt blocklist jest lock-free (ArcSwap epoch load + przeszukanie trie).
    pub fn check_blocklist(&self, domain: &str) -> BlocklistVerdict {
        if !self.enabled.load(Ordering::Acquire) {
            return BlocklistVerdict::Allow;
        }

        if self.blocklist.load().is_blocked(domain) {
            BlocklistVerdict::Block(format!(
                "Domain '{}' is blocklisted",
                domain.trim_end_matches('.').to_lowercase(),
            ))
        } else {
            BlocklistVerdict::Allow
        }
    }

    /// Analizuje zapytanie DNS pod kątem tunelowania i zwraca werdykt bezpieczeństwa.
    ///
    /// Blokuje `Mutex<TunnelingDetector>` na krótko (hash lookup + insert statystyk).
    pub fn inspect_tunneling(&self, fqdn: &str, qtype: &DnsRecordType) -> DnsInspectionVerdict {
        if !self.enabled.load(Ordering::Acquire) {
            return DnsInspectionVerdict::Allow;
        }

        self.tunneling.lock().unwrap().inspect(fqdn, qtype)
    }

    /// Sprawdza odpowiedź DNS pod kątem wskazówek ECH w rekordach HTTPS/SVCB.
    ///
    /// Wywoływana wyłącznie dla odpowiedzi DNS (`is_response == true`).
    /// Emituje zdarzenie `EchAttemptDetected` gdy polityka to nakazuje i — gdy
    /// `strip_ech_dns` — zwraca `Block`, co skutkuje odrzuceniem odpowiedzi.
    pub fn inspect_ech(&self, domain: &str, has_ech_hints: bool) -> EchMitigationVerdict {
        if !self.enabled.load(Ordering::Acquire) || !has_ech_hints {
            return EchMitigationVerdict::Allow;
        }

        let cfg = self.ech_mitigation.load();
        let action = if cfg.strip_ech_dns {
            EchAction::Stripped
        } else {
            EchAction::Logged
        };

        if cfg.log_ech_attempts {
            tracing::info!(domain = %domain, "ECH config detected in DNS response (HTTPS/SVCB record)");
            events::emit(events::Event::new(events::EventKind::EchAttemptDetected {
                source_ip: None,
                domain: domain.to_string(),
                origin: EchOrigin::DnsHttpsRecord,
                action,
            }));
        }

        if cfg.strip_ech_dns {
            EchMitigationVerdict::Block(format!(
                "ECH: DNS response for '{domain}' blocked (HTTPS/SVCB record)"
            ))
        } else {
            EchMitigationVerdict::Allow
        }
    }

    /// Granularna aktualizacja konfiguracji bez resetowania statystyk i cache.
    ///
    /// Kolejność aktualizacji:
    /// 1. `enabled` — atomowy store
    /// 2. `blocklist` — nowe drzewo przez ArcSwap (stare wersje żyją do ostatniego Arc::drop)
    /// 3. `tunneling` — `update_config()` zachowuje statystyki per-domena
    /// 4. `dnssec` — rebuild silnika tylko przy zmianie resolvera lub cache; w przeciwnym razie
    ///    aktualizuje konfigurację w miejscu zachowując cache DNSSEC
    pub fn update_config(&self, config: &DnsInspectionConfig) -> Result<()> {
        self.enabled.store(config.general.enabled, Ordering::Release);

        self.blocklist.store(Arc::new(DomainBlockTree::from_config(&config.blocklist)));

        self.tunneling.lock()
            .map_err(|e| anyhow::anyhow!("Tunneling detector mutex poisoned: {e}"))?
            .update_config(config.dns_tunneling.clone());

        let current = self.dnssec.load_full();
        let current_config = current.config();

        if current_config.resolver != config.dnssec.resolver || current_config.cache != config.dnssec.cache
        {
            // Resolver lub ustawienia cache się zmieniły — przebuduj silnik (cache zostaje utracony).
            let new_engine = Arc::new(DnssecEngine::new(config.dnssec.clone())?);
            self.dnssec.store(Arc::new(new_engine));
        } else {
            // Aktualizuj w miejscu i zachowaj cache.
            current.update_non_resolver_config(config.dnssec.clone());
        }

        self.ech_mitigation.store(Arc::new(config.ech_mitigation.clone()));

        Ok(())
    }
}

/// Implementacja `DnssecProvider` dla `DnsInspection` — wstrzykiwana do
/// [`PolicyEvaluator`][crate::policy::policy_evaluator::PolicyEvaluator] i wywoływana
/// leniwie przez reguły RaptorLang (`match dns_dnssec_status { ... }`).
///
/// Uwaga: `check_domain` może wykonywać blokujące operacje sieciowe.
/// W kontekście async należy opakowywać wywołanie przez `tokio::task::spawn_blocking`.
impl DnssecProvider for DnsInspection {
    fn check_domain(&self, domain: &str, qtype: Option<DnsRecordType>) -> DnssecResult {
        if !self.enabled.load(Ordering::Acquire) {
            return DnssecResult::not_checked();
        }

        // Lock-free clone Arc<DnssecEngine> — koszt to tylko increment licznika referencji.
        let engine = self.dnssec.load_full();
        engine.check_domain(domain, qtype)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::dpi::parsers::dns::DnsRecordType;
    use crate::data_plane::dns_inspection::types::DnssecStatus;
    use crate::data_plane::dns_inspection::config::{
        DnsInspectionBlocklistConfig, DnsInspectionDnsTunnelingConfig,
        DnsInspectionDnssecConfig, DnsInspectionEchMitigationConfig, DnsInspectionGeneralConfig,
    };

    fn make_config() -> DnsInspectionConfig {
        DnsInspectionConfig {
            general: DnsInspectionGeneralConfig { enabled: true },
            blocklist: DnsInspectionBlocklistConfig {
                enabled: true,
                domains: vec!["blocked.com".into()],
            },
            dns_tunneling: DnsInspectionDnsTunnelingConfig {
                enabled: true,
                ..Default::default()
            },
            dnssec: DnsInspectionDnssecConfig::default(),
            ech_mitigation: DnsInspectionEchMitigationConfig::default(),
        }
    }

    fn make_inspection() -> Arc<DnsInspection> {
        DnsInspection::new(make_config()).unwrap()
    }

    #[test]
    fn blocklisted_domain_returns_block() {
        let ins = make_inspection();
        assert!(matches!(ins.check_blocklist("blocked.com"), BlocklistVerdict::Block(_)));
    }

    #[test]
    fn clean_domain_allow() {
        let ins = make_inspection();
        assert!(matches!(ins.check_blocklist("example.com"), BlocklistVerdict::Allow));
    }

    #[test]
    fn tunneling_clean_domain_allow() {
        let ins = make_inspection();
        assert_eq!(
            ins.inspect_tunneling("example.com", &DnsRecordType::A),
            DnsInspectionVerdict::Allow,
        );
    }

    #[test]
    fn global_disable_blocks_nothing() {
        let mut config = make_config();
        config.general.enabled = false;
        let ins = DnsInspection::new(config).unwrap();

        assert!(matches!(ins.check_blocklist("blocked.com"), BlocklistVerdict::Allow));
        assert_eq!(
            ins.inspect_tunneling("blocked.com", &DnsRecordType::Txt),
            DnsInspectionVerdict::Allow,
        );
    }

    #[test]
    fn update_config_hot_swaps_blocklist() {
        let ins = make_inspection();

        assert!(matches!(ins.check_blocklist("blocked.com"), BlocklistVerdict::Block(_)));

        let mut new_config = make_config();
        new_config.blocklist.domains = vec!["new-blocked.com".into()];
        ins.update_config(&new_config).unwrap();

        assert!(matches!(ins.check_blocklist("blocked.com"), BlocklistVerdict::Allow));
        assert!(matches!(ins.check_blocklist("new-blocked.com"), BlocklistVerdict::Block(_)));
    }

    #[test]
    fn dnssec_disabled_returns_not_checked() {
        let ins = make_inspection();
        let result = ins.check_domain("example.com", Some(DnsRecordType::A));
        // Silnik jest wyłączony w domyślnej konfiguracji (enabled: false)
        assert_eq!(result.status, DnssecStatus::NotChecked);
    }

    #[test]
    fn global_disable_skips_dnssec() {
        let mut config = make_config();
        config.general.enabled = false;
        let ins = DnsInspection::new(config).unwrap();
        let result = ins.check_domain("example.com", Some(DnsRecordType::A));
        assert_eq!(result.status, DnssecStatus::NotChecked);
    }
}
