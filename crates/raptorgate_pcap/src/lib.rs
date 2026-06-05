pub mod error;
pub mod features;
pub mod flow_id;
pub mod index;
pub mod labels;
pub mod output;
pub mod parse;
pub mod stats;

use std::path::PathBuf;
use std::sync::Arc;

use pyo3::prelude::*;

use ngfw::dpi::DpiClassifier;

use crate::error::{PcapError, Result};
use crate::features::{build_features as build_features_rs, BuildOptions};
use crate::index::MappedPcap;
use crate::labels::PyLabelIndex;
use crate::output::{FeatureOutput, PyFeatureOutput};

const FEATURE_NAMES: &[&str] = &[
    "proto",
    "ip_ver_v6",
    "dst_port_class",
    "src_port_log",
    "dst_port_log",
    "payload_len_log",
    "iat_log",
    "ttl_norm",
    "tcp_syn",
    "tcp_ack",
    "tcp_fin",
    "tcp_rst",
    "tcp_psh",
    "tcp_window_log",
    "app_proto",
    "tls_version",
    "tls_ech_detected",
    "sni_entropy",
    "sni_len",
    "alpn_hash_bucket",
    "http_method",
    "host_entropy",
    "ua_hash_bucket",
    "payload_entropy",
    "qname_entropy",
    "qname_len",
    "label_max_len",
    "qtype",
    "answer_count",
    "rcode",
    "hour_sin",
    "hour_cos",
    "zone_pair_bucket",
    "pinning_failures_60s",
    "unique_dst_60s_log",
    "syn_rate_60s_log",
    "nxdomain_ratio_60s",
    "new_flow_rate_60s_log",
];

#[pyfunction]
#[pyo3(signature = (pcap_path, label_index, window_secs=60.0, num_workers=None))]
fn build_features_py(
    py: Python<'_>,
    pcap_path: PathBuf,
    label_index: &PyLabelIndex,
    window_secs: f64,
    num_workers: Option<usize>,
) -> PyResult<PyFeatureOutput> {
    let owned_idx = label_index.inner.clone();
    if std::env::var("RG_LIB_DEBUG").is_ok() {
        eprintln!(
            "[lib.rs] build_features_py: cloned label_index len={} has_timed={} timed_rows={} indexed_rows={} source_rows={} pcap={}",
            owned_idx.len(),
            owned_idx.has_timed(),
            owned_idx.stats.timed_rows,
            owned_idx.stats.indexed_rows,
            owned_idx.stats.source_rows,
            pcap_path.display()
        );
    }
    let opts = BuildOptions {
        window_secs,
        num_workers,
        ..Default::default()
    };
    let out = py
        .detach(|| -> Result<FeatureOutput> {
            eprintln!("[raptorgate-pcap] py.detach: opening {}", pcap_path.display());
            let mapped = MappedPcap::open(&pcap_path)?;
            eprintln!("[raptorgate-pcap] py.detach: mmap ok linktype={}", mapped.linktype());
            let classifier = Arc::new(DpiClassifier::new());
            eprintln!("[raptorgate-pcap] py.detach: starting build_features_rs");
            let r = build_features_rs(&mapped, &owned_idx, classifier, opts);
            eprintln!("[raptorgate-pcap] py.detach: build_features_rs returned");
            r
        })
        .map_err(pyo3_error)?;
    eprintln!("[raptorgate-pcap] build_features_py: returning n_rows={}", out.n_rows);
    Ok(PyFeatureOutput::from(out))
}

#[pyfunction]
fn feature_names_py() -> Vec<String> {
    FEATURE_NAMES.iter().map(|s| s.to_string()).collect()
}

fn pyo3_error(e: PcapError) -> PyErr {
    pyo3::exceptions::PyValueError::new_err(e.to_string())
}

#[pymodule]
fn raptorgate_pcap(m: &Bound<'_, PyModule>) -> PyResult<()> {
    m.add("__version__", env!("CARGO_PKG_VERSION"))?;
    m.add_class::<labels::PyLabelIndex>()?;
    m.add_class::<output::PyFeatureOutput>()?;
    m.add_function(wrap_pyfunction!(build_features_py, m)?)?;
    m.add_function(wrap_pyfunction!(feature_names_py, m)?)?;
    Ok(())
}
