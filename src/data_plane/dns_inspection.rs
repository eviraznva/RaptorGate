use std::sync::Arc;
use rustc_hash::FxHashMap;

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

/// Inspektor DNS — przechowuje listę blokowanych domen i sprawdza payloady UDP.
pub struct DnsInspection {
    blocklist: DomainBlockTree,
}

impl DnsInspection {
    pub fn new(blocklist: DomainBlockTree) -> Arc<Self> {
        Arc::new(Self { blocklist })
    }

    /// Sprawdza payload UDP pod kątem DNS query.
    /// Zwraca `true` jeśli zapytana domena jest na liście blokowanych.
    pub fn process(&self, dns_payload: &[u8]) -> bool {
        match Self::extract_query_domain(dns_payload) {
            Some(domain) => self.blocklist.is_blocked(&domain),
            None => false,
        }
    }

    /// Wyciąga nazwę domeny z pierwszej sekcji Question pakietu DNS.
    /// Zwraca `None` jeśli payload nie jest poprawnym DNS query.
    fn extract_query_domain(payload: &[u8]) -> Option<String> {
        if payload.len() < 12 {
            return None;
        }

        // Bit QR (bit 15 w flags) musi być 0 — query, nie response
        let flags = u16::from_be_bytes([payload[2], payload[3]]);
        if flags & 0x8000 != 0 {
            return None;
        }

        // QDCOUNT musi być >= 1
        let qdcount = u16::from_be_bytes([payload[4], payload[5]]);

        if qdcount == 0 {
            return None;
        }

        // Parsowanie nazwy domeny zaczynając od bajtu 12 (po 12-bajtowym nagłówku)
        let mut pos = 12usize;
        let mut labels: Vec<String> = Vec::new();

        loop {
            if pos >= payload.len() {
                return None;
            }

            let len = payload[pos] as usize;

            if len == 0 {
                break;
            }

            // Wskaźnik kompresji (top 2 bity = 11) — nieoczekiwany w sekcji Question
            if len & 0xC0 == 0xC0 {
                return None;
            }

            pos += 1;

            if pos + len > payload.len() {
                return None;
            }

            let label = std::str::from_utf8(&payload[pos..pos + len]).ok()?;
            labels.push(label.to_string());

            pos += len;
        }

        if labels.is_empty() {
            return None;
        }

        Some(labels.join("."))
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