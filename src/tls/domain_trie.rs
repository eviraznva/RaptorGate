use std::collections::HashMap;

// Trie dopasowujące domeny po odwróconych labelach — O(k) lookup.
#[derive(Debug, Default)]
pub struct DomainTrie {
    root: TrieNode,
}

#[derive(Debug, Default)]
struct TrieNode {
    terminal: bool,
    children: HashMap<Box<str>, TrieNode>,
}

impl DomainTrie {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn insert(&mut self, domain: &str) {
        let normalized = domain.trim().to_lowercase();
        if normalized.is_empty() {
            return;
        }
        let labels: Vec<&str> = normalized.split('.').rev().collect();
        let mut node = &mut self.root;
        for label in labels {
            node = node
                .children
                .entry(label.into())
                .or_default();
        }
        node.terminal = true;
    }

    pub fn contains(&self, domain: &str) -> bool {
        let normalized = domain.trim().to_lowercase();
        if normalized.is_empty() {
            return false;
        }
        let labels: Vec<&str> = normalized.split('.').rev().collect();
        let mut node = &self.root;
        for label in &labels {
            match node.children.get(*label) {
                Some(child) => {
                    if child.terminal {
                        return true;
                    }
                    node = child;
                }
                None => return false,
            }
        }
        node.terminal
    }

    pub fn from_domains(domains: &[String]) -> Self {
        let mut trie = Self::new();
        for d in domains {
            trie.insert(d);
        }
        trie
    }

    pub fn is_empty(&self) -> bool {
        self.root.children.is_empty()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn exact_match() {
        let mut trie = DomainTrie::new();
        trie.insert("example.com");
        assert!(trie.contains("example.com"));
    }

    #[test]
    fn subdomain_match() {
        let mut trie = DomainTrie::new();
        trie.insert("example.com");
        assert!(trie.contains("www.example.com"));
        assert!(trie.contains("deep.sub.example.com"));
    }

    #[test]
    fn no_match() {
        let mut trie = DomainTrie::new();
        trie.insert("example.com");
        assert!(!trie.contains("notexample.com"));
        assert!(!trie.contains("example.org"));
    }

    #[test]
    fn case_insensitive() {
        let mut trie = DomainTrie::new();
        trie.insert("example.com");
        assert!(trie.contains("EXAMPLE.COM"));
        assert!(trie.contains("Www.Example.COM"));
    }

    #[test]
    fn empty_list() {
        let trie = DomainTrie::new();
        assert!(!trie.contains("example.com"));
    }

    #[test]
    fn multiple_entries() {
        let mut trie = DomainTrie::new();
        trie.insert("bank.com");
        trie.insert("gov.pl");
        assert!(trie.contains("www.bank.com"));
        assert!(trie.contains("portal.gov.pl"));
        assert!(!trie.contains("example.com"));
    }

    #[test]
    fn from_domains_constructor() {
        let domains = vec!["example.com".into(), "test.org".into()];
        let trie = DomainTrie::from_domains(&domains);
        assert!(trie.contains("example.com"));
        assert!(trie.contains("sub.test.org"));
        assert!(!trie.contains("other.net"));
    }

    #[test]
    fn empty_domain_ignored() {
        let mut trie = DomainTrie::new();
        trie.insert("");
        trie.insert("  ");
        assert!(trie.is_empty());
    }

    #[test]
    fn tld_blocks_all_subdomains() {
        let mut trie = DomainTrie::new();
        trie.insert("pl");
        assert!(trie.contains("gov.pl"));
        assert!(trie.contains("example.pl"));
        assert!(!trie.contains("com"));
    }

    #[test]
    fn partial_prefix_no_match() {
        let mut trie = DomainTrie::new();
        trie.insert("sub.example.com");
        assert!(trie.contains("sub.example.com"));
        assert!(trie.contains("deep.sub.example.com"));
        assert!(!trie.contains("example.com"));
        assert!(!trie.contains("other.example.com"));
    }
}
