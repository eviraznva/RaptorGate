/// Zwraca `true`, jeśli env jest ustawione na wartość prawdziwą.
pub fn env_flag(name: &str) -> bool {
    match std::env::var(name) {
        Ok(value) => matches!(
            value.trim().to_ascii_lowercase().as_str(),
            "1" | "true" | "yes" | "on"
        ),
        Err(_) => false,
    }
}

/// Buduje krótki preview payloadu w hex do logów `TRACE`.
pub fn payload_preview_hex(bytes: &[u8], limit: usize) -> String {
    let preview_len = bytes.len().min(limit);
    
    let mut output = String::new();

    for (idx, byte) in bytes[..preview_len].iter().enumerate() {
        if idx > 0 {
            output.push(' ');
        }

        use std::fmt::Write as _;

        let _ = write!(&mut output, "{byte:02X}");
    }

    if bytes.len() > limit {
        output.push_str(" ...");
    }

    output
}
