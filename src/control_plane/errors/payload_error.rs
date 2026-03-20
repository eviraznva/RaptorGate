/// Błędy kodowania i dekodowania payloadów wiadomości IPC.
#[derive(thiserror::Error, Debug)]
pub enum PayloadError {
    #[error("failed to read payload field `{field}`")]
    TruncatedField { field: &'static str },
    
    #[error("invalid boolean value in field `{field}`: {value}")]
    InvalidBool { field: &'static str, value: u32 },
    
    #[error("invalid enum value in field `{field}`: {value}")]
    InvalidEnumValue { field: &'static str, value: u32 },
    
    #[error("invalid UTF-8 string in field `{field}`")]
    InvalidUtf8 { field: &'static str },
    
    #[error("payload contains {remaining} trailing bytes")]
    TrailingBytes { remaining: usize },
}
