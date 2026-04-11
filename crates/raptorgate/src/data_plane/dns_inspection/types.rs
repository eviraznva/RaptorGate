use std::fmt;

/// Wynik walidacji DNSSEC dla danej domeny.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DnssecStatus {
    /// Rekord DNS jest poprawnie podpisany cyfrowo i przeszedł pełną walidację łańcucha zaufania.
    Secure,
    /// Rekord DNS istnieje, ale strefa nie jest podpisana DNSSEC — brak weryfikacji.
    Insecure,
    /// Podpis DNSSEC jest nieprawidłowy lub łańcuch zaufania jest zerwany.
    Bogus,
    /// Resolver nie odpowiedział w skonfigurowanym czasie oczekiwania.
    Timeout,
    /// Wystąpił nieoczekiwany błąd podczas walidacji (błąd sieci, parsowania itp.).
    Error,
    /// Walidacja nie została przeprowadzona — moduł DNSSEC jest wyłączony lub brak domeny.
    NotChecked,
}

impl fmt::Display for DnssecStatus {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let s = match self {
            DnssecStatus::Secure     => "secure",
            DnssecStatus::Insecure   => "insecure",
            DnssecStatus::Bogus      => "bogus",
            DnssecStatus::Timeout    => "timeout",
            DnssecStatus::Error      => "error",
            DnssecStatus::NotChecked => "not_checked",
        };
        f.write_str(s)
    }
}
