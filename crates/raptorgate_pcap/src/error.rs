use pyo3::exceptions::PyValueError;
use pyo3::prelude::*;

#[derive(Debug, thiserror::Error)]
pub enum PcapError {
    #[error("pcap open: {0}")]
    PcapOpen(#[source] std::io::Error),

    #[error("pcap parse: {0}")]
    PcapParse(String),

    #[error("etherparse: {0}")]
    Etherparse(#[from] etherparse::err::ReadError),

    #[error("mmap: {0}")]
    Mmap(#[source] std::io::Error),

    #[error("invalid label tuple at row {row}")]
    InvalidLabelTuple { row: usize },
}

impl From<PcapError> for PyErr {
    fn from(err: PcapError) -> PyErr {
        PyValueError::new_err(err.to_string())
    }
}

pub type Result<T> = std::result::Result<T, PcapError>;
