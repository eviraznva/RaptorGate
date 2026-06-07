use std::collections::HashMap;
use std::net::IpAddr;
use std::str::FromStr;
use std::sync::atomic::{AtomicUsize, Ordering};

use pyo3::exceptions::PyValueError;
use pyo3::prelude::*;
use pyo3::types::PyAny;

use crate::flow_id::flow_id_for;

pub const LABEL_BENIGN: u8 = 0;
pub const LABEL_MALICIOUS: u8 = 1;

pub const UNMATCHED_ATTACK: &str = "unmatched";
pub const BENIGN_ATTACK: &str = "BENIGN";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct LabelMatch {
    pub label_code: u8,
    pub attack_idx: u32,
    pub matched: bool,
}

static MATCH_TRACE: AtomicUsize = AtomicUsize::new(0);

#[derive(Debug, Clone)]
struct TimeWindow {
    start_ts: f64,
    end_ts: f64,
    label_code: u8,
    attack_idx: u32,
}

#[derive(Debug, Clone)]
struct Entry {
    label_code: u8,
    attack_idx: u32,
    windows: Vec<TimeWindow>,
}

#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub struct LabelIndexStats {
    pub source_rows: usize,
    pub indexed_rows: usize,
    pub null_labels: usize,
    pub invalid_rows: usize,
    pub timed_rows: usize,
}

#[derive(Debug, Clone, Copy)]
pub struct LabelRow<'a> {
    pub src_ip: IpAddr,
    pub dst_ip: IpAddr,
    pub src_port: u16,
    pub dst_port: u16,
    pub proto: u8,
    pub raw_label: &'a str,
    pub raw_attack_label: Option<&'a str>,
    pub timestamp: Option<f64>,
    pub flow_duration_us: Option<u64>,
}

#[derive(Debug, Clone)]
pub struct LabelIndex {
    by_flow_id: HashMap<u64, Entry>,
    attack_names: Vec<String>,
    attack_lookup: HashMap<String, u32>,
    has_timed: bool,
    pub stats: LabelIndexStats,
}

impl Default for LabelIndex {
    fn default() -> Self {
        let mut idx = Self {
            by_flow_id: HashMap::new(),
            attack_names: Vec::new(),
            attack_lookup: HashMap::new(),
            has_timed: false,
            stats: LabelIndexStats::default(),
        };
        let unmatched = idx.intern_attack(UNMATCHED_ATTACK);
        debug_assert_eq!(unmatched, 0);
        idx
    }
}

impl LabelIndex {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn len(&self) -> usize {
        self.by_flow_id.len()
    }

    pub fn is_empty(&self) -> bool {
        self.by_flow_id.is_empty()
    }

    pub fn attack_name(&self, idx: u32) -> Option<&str> {
        self.attack_names.get(idx as usize).map(String::as_str)
    }

    pub fn attack_names(&self) -> &[String] {
        &self.attack_names
    }

    pub fn has_timed(&self) -> bool {
        self.has_timed
    }

    pub fn unmatched(&self) -> LabelMatch {
        LabelMatch {
            label_code: LABEL_BENIGN,
            attack_idx: 0,
            matched: false,
        }
    }

    pub fn match_for(&self, flow_id: u64, ts: Option<f64>) -> LabelMatch {
        let entry = self.by_flow_id.get(&flow_id);
        if std::env::var("RG_MATCH_DEBUG").is_ok() {
            let n = MATCH_TRACE.fetch_add(1, Ordering::Relaxed);
            if n < 5 {
                eprintln!(
                    "[match_for] call[{n}] flow_id={flow_id:#x} ts={ts:?} has_timed={} entry_present={} windows={}",
                    self.has_timed,
                    entry.is_some(),
                    entry.map(|e| e.windows.len()).unwrap_or(0),
                );
                if let Some(e) = entry {
                    for (i, w) in e.windows.iter().take(3).enumerate() {
                        eprintln!(
                            "[match_for]   window[{i}] start_ts={} end_ts={} label_code={} attack_idx={}",
                            w.start_ts, w.end_ts, w.label_code, w.attack_idx
                        );
                    }
                }
            }
        }
        if let (Some(t), true) = (ts, self.has_timed) {
            let Some(entry) = entry else {
                return self.unmatched();
            };
            for w in &entry.windows {
                if w.start_ts - 1.0 <= t && t <= w.end_ts + 1.0 {
                    return LabelMatch {
                        label_code: w.label_code,
                        attack_idx: w.attack_idx,
                        matched: true,
                    };
                }
            }
            return self.unmatched();
        }
        match entry {
            Some(e) => LabelMatch {
                label_code: e.label_code,
                attack_idx: e.attack_idx,
                matched: true,
            },
            None => self.unmatched(),
        }
    }

    pub fn insert_row(&mut self, row: LabelRow<'_>) {
        self.stats.source_rows += 1;

        let Some(label_code) = normalize_label(row.raw_label) else {
            self.stats.null_labels += 1;
            return;
        };
        let attack_str = row
            .raw_attack_label
            .filter(|s| !s.trim().is_empty())
            .map(str::trim)
            .map(str::to_owned)
            .unwrap_or_else(|| derive_attack_label(label_code, row.raw_label));
        let attack_idx = self.intern_attack(&attack_str);

        let flow_id = flow_id_for(row.proto, row.src_ip, row.src_port, row.dst_ip, row.dst_port);

        let entry = self
            .by_flow_id
            .entry(flow_id)
            .or_insert_with(|| Entry {
                label_code,
                attack_idx,
                windows: Vec::new(),
            });

        if let Some(start_ts) = row.timestamp {
            let duration_secs = row.flow_duration_us.unwrap_or(0) as f64 / 1_000_000.0;
            let end_ts = start_ts + duration_secs.max(1.0);
            entry.windows.push(TimeWindow {
                start_ts,
                end_ts,
                label_code,
                attack_idx,
            });
            self.has_timed = true;
            self.stats.timed_rows += 1;
        }

        self.stats.indexed_rows += 1;
    }

    fn intern_attack(&mut self, name: &str) -> u32 {
        if let Some(&idx) = self.attack_lookup.get(name) {
            return idx;
        }
        let idx = self.attack_names.len() as u32;
        self.attack_names.push(name.to_string());
        self.attack_lookup.insert(name.to_string(), idx);
        idx
    }
}

pub fn normalize_label(raw: &str) -> Option<u8> {
    let u = raw.trim().to_ascii_uppercase();
    if matches!(u.as_str(), "" | "NULL" | "NONE" | "NAN") {
        return None;
    }
    Some(if u == "BENIGN" { LABEL_BENIGN } else { LABEL_MALICIOUS })
}

fn derive_attack_label(label_code: u8, raw_label: &str) -> String {
    if label_code == LABEL_BENIGN {
        BENIGN_ATTACK.to_string()
    } else {
        raw_label.trim().to_string()
    }
}

#[pyclass(name = "LabelIndex", module = "raptorgate_pcap")]
pub struct PyLabelIndex {
    pub inner: LabelIndex,
}

#[pymethods]
impl PyLabelIndex {
    #[new]
    fn py_new() -> Self {
        Self {
            inner: LabelIndex::new(),
        }
    }

    fn __len__(&self) -> usize {
        self.inner.len()
    }

    #[getter]
    fn flow_count(&self) -> usize {
        self.inner.len()
    }

    #[getter]
    fn attack_names(&self) -> Vec<String> {
        self.inner.attack_names().to_vec()
    }

    #[getter]
    fn source_rows(&self) -> usize {
        self.inner.stats.source_rows
    }

    #[getter]
    fn indexed_rows(&self) -> usize {
        self.inner.stats.indexed_rows
    }

    #[getter]
    fn null_labels(&self) -> usize {
        self.inner.stats.null_labels
    }

    #[getter]
    fn invalid_rows(&self) -> usize {
        self.inner.stats.invalid_rows
    }

    #[getter]
    fn timed_rows(&self) -> usize {
        self.inner.stats.timed_rows
    }

    #[pyo3(signature = (flow_id, ts=None))]
    fn match_for(&self, flow_id: u64, ts: Option<f64>) -> (u8, u32, bool) {
        let m = self.inner.match_for(flow_id, ts);
        (m.label_code, m.attack_idx, m.matched)
    }

    fn absorb_arrow(&mut self, table: &Bound<'_, PyAny>) -> PyResult<()> {
        let src_ip: Vec<Option<String>> = column_to_pylist(table, "src_ip")?.extract()?;
        let dst_ip: Vec<Option<String>> = column_to_pylist(table, "dst_ip")?.extract()?;
        let src_port: Vec<Option<i64>> = column_to_pylist(table, "src_port")?.extract()?;
        let dst_port: Vec<Option<i64>> = column_to_pylist(table, "dst_port")?.extract()?;
        let proto: Vec<Option<i64>> = column_to_pylist(table, "proto")?.extract()?;
        let label: Vec<Option<String>> = column_to_pylist(table, "label")?.extract()?;

        let n = src_ip.len();
        if dst_ip.len() != n
            || src_port.len() != n
            || dst_port.len() != n
            || proto.len() != n
            || label.len() != n
        {
            return Err(PyValueError::new_err(
                "column lengths must match in absorb_arrow",
            ));
        }

        let attack_label = optional_string_column(table, "attack_label", n)?;
        let timestamp = optional_f64_column(table, "timestamp", n)?;
        let flow_duration_us = optional_u64_column(table, "flow_duration_us", n)?;

        for row in 0..n {
            let (Some(src_ip_s), Some(dst_ip_s), Some(sp), Some(dp), Some(pr), Some(lbl)) = (
                src_ip[row].as_deref(),
                dst_ip[row].as_deref(),
                src_port[row],
                dst_port[row],
                proto[row],
                label[row].as_deref(),
            ) else {
                self.inner.stats.source_rows += 1;
                self.inner.stats.null_labels += 1;
                continue;
            };
            let (Ok(src), Ok(dst)) = (IpAddr::from_str(src_ip_s), IpAddr::from_str(dst_ip_s))
            else {
                self.inner.stats.source_rows += 1;
                self.inner.stats.invalid_rows += 1;
                continue;
            };
            let (sp, dp, pr) = match (u16::try_from(sp), u16::try_from(dp), u8::try_from(pr)) {
                (Ok(sp), Ok(dp), Ok(pr)) => (sp, dp, pr),
                _ => {
                    self.inner.stats.source_rows += 1;
                    self.inner.stats.invalid_rows += 1;
                    continue;
                }
            };
            self.inner.insert_row(LabelRow {
                src_ip: src,
                dst_ip: dst,
                src_port: sp,
                dst_port: dp,
                proto: pr,
                raw_label: lbl,
                raw_attack_label: attack_label[row].as_deref(),
                timestamp: timestamp[row],
                flow_duration_us: flow_duration_us[row],
            });
        }
        Ok(())
    }
}

fn column_to_pylist<'py>(
    table: &Bound<'py, PyAny>,
    name: &str,
) -> PyResult<Bound<'py, PyAny>> {
    let column = table.call_method1("column", (name,))?;
    column.call_method0("to_pylist")
}

fn optional_string_column(
    table: &Bound<'_, PyAny>,
    name: &str,
    expected_len: usize,
) -> PyResult<Vec<Option<String>>> {
    if !has_column(table, name)? {
        return Ok(vec![None; expected_len]);
    }
    let values: Vec<Option<String>> = column_to_pylist(table, name)?.extract()?;
    if values.len() != expected_len {
        return Err(PyValueError::new_err(format!(
            "column {name} length mismatch"
        )));
    }
    Ok(values)
}

fn optional_f64_column(
    table: &Bound<'_, PyAny>,
    name: &str,
    expected_len: usize,
) -> PyResult<Vec<Option<f64>>> {
    if !has_column(table, name)? {
        return Ok(vec![None; expected_len]);
    }
    let values: Vec<Option<f64>> = column_to_pylist(table, name)?.extract()?;
    if values.len() != expected_len {
        return Err(PyValueError::new_err(format!(
            "column {name} length mismatch"
        )));
    }
    Ok(values)
}

fn optional_u64_column(
    table: &Bound<'_, PyAny>,
    name: &str,
    expected_len: usize,
) -> PyResult<Vec<Option<u64>>> {
    if !has_column(table, name)? {
        return Ok(vec![None; expected_len]);
    }
    let values: Vec<Option<i64>> = column_to_pylist(table, name)?.extract()?;
    if values.len() != expected_len {
        return Err(PyValueError::new_err(format!(
            "column {name} length mismatch"
        )));
    }
    Ok(values
        .into_iter()
        .map(|v| v.and_then(|n| if n < 0 { None } else { Some(n as u64) }))
        .collect())
}

fn has_column(table: &Bound<'_, PyAny>, name: &str) -> PyResult<bool> {
    let names: Vec<String> = table.getattr("column_names")?.extract()?;
    Ok(names.iter().any(|n| n == name))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::Ipv4Addr;

    fn ip(a: u8, b: u8, c: u8, d: u8) -> IpAddr {
        IpAddr::V4(Ipv4Addr::new(a, b, c, d))
    }

    #[allow(clippy::too_many_arguments)]
    fn row<'a>(
        src: IpAddr,
        dst: IpAddr,
        sp: u16,
        dp: u16,
        proto: u8,
        label: &'a str,
        attack: Option<&'a str>,
        ts: Option<f64>,
        dur_us: Option<u64>,
    ) -> LabelRow<'a> {
        LabelRow {
            src_ip: src,
            dst_ip: dst,
            src_port: sp,
            dst_port: dp,
            proto,
            raw_label: label,
            raw_attack_label: attack,
            timestamp: ts,
            flow_duration_us: dur_us,
        }
    }

    #[test]
    fn empty_index_returns_unmatched() {
        let idx = LabelIndex::new();
        let m = idx.match_for(0, None);
        assert!(!m.matched);
        assert_eq!(m.label_code, LABEL_BENIGN);
        assert_eq!(m.attack_idx, 0);
        assert_eq!(idx.attack_name(0), Some(UNMATCHED_ATTACK));
    }

    #[test]
    fn normalize_label_cases() {
        assert_eq!(normalize_label("BENIGN"), Some(LABEL_BENIGN));
        assert_eq!(normalize_label("  benign "), Some(LABEL_BENIGN));
        assert_eq!(normalize_label("DDoS"), Some(LABEL_MALICIOUS));
        assert_eq!(normalize_label(""), None);
        assert_eq!(normalize_label("null"), None);
        assert_eq!(normalize_label("NaN"), None);
    }

    #[test]
    fn insert_and_lookup_canonical_flow() {
        let mut idx = LabelIndex::new();
        idx.insert_row(row(
            ip(10, 0, 0, 1),
            ip(10, 0, 0, 2),
            12345,
            443,
            6,
            "DDoS",
            None,
            None,
            None,
        ));
        let fid = flow_id_for(6, ip(10, 0, 0, 1), 12345, ip(10, 0, 0, 2), 443);
        let m = idx.match_for(fid, None);
        assert!(m.matched);
        assert_eq!(m.label_code, LABEL_MALICIOUS);
        assert_eq!(idx.attack_name(m.attack_idx), Some("DDoS"));
    }

    #[test]
    fn lookup_reversed_direction_finds_same_entry() {
        let mut idx = LabelIndex::new();
        idx.insert_row(row(
            ip(10, 0, 0, 1),
            ip(10, 0, 0, 2),
            12345,
            443,
            6,
            "BENIGN",
            None,
            None,
            None,
        ));
        let fid_rev = flow_id_for(6, ip(10, 0, 0, 2), 443, ip(10, 0, 0, 1), 12345);
        let m = idx.match_for(fid_rev, None);
        assert!(m.matched);
        assert_eq!(m.label_code, LABEL_BENIGN);
        assert_eq!(idx.attack_name(m.attack_idx), Some(BENIGN_ATTACK));
    }

    #[test]
    fn benign_label_derives_benign_attack() {
        let mut idx = LabelIndex::new();
        idx.insert_row(row(
            ip(1, 1, 1, 1),
            ip(2, 2, 2, 2),
            1000,
            80,
            6,
            "benign",
            None,
            None,
            None,
        ));
        let fid = flow_id_for(6, ip(1, 1, 1, 1), 1000, ip(2, 2, 2, 2), 80);
        let m = idx.match_for(fid, None);
        assert!(m.matched);
        assert_eq!(idx.attack_name(m.attack_idx), Some(BENIGN_ATTACK));
    }

    #[test]
    fn explicit_attack_label_overrides() {
        let mut idx = LabelIndex::new();
        idx.insert_row(row(
            ip(1, 1, 1, 1),
            ip(2, 2, 2, 2),
            1000,
            80,
            6,
            "malicious",
            Some("PortScan"),
            None,
            None,
        ));
        let fid = flow_id_for(6, ip(1, 1, 1, 1), 1000, ip(2, 2, 2, 2), 80);
        let m = idx.match_for(fid, None);
        assert!(m.matched);
        assert_eq!(idx.attack_name(m.attack_idx), Some("PortScan"));
    }

    #[test]
    fn null_label_increments_null_counter() {
        let mut idx = LabelIndex::new();
        idx.insert_row(row(
            ip(1, 1, 1, 1),
            ip(2, 2, 2, 2),
            1000,
            80,
            6,
            "",
            None,
            None,
            None,
        ));
        assert_eq!(idx.stats.source_rows, 1);
        assert_eq!(idx.stats.null_labels, 1);
        assert_eq!(idx.stats.indexed_rows, 0);
        assert!(idx.is_empty());
    }

    #[test]
    fn timed_match_within_window() {
        let mut idx = LabelIndex::new();
        idx.insert_row(row(
            ip(10, 0, 0, 1),
            ip(10, 0, 0, 2),
            12345,
            443,
            6,
            "DDoS",
            None,
            Some(1_000.0),
            Some(5_000_000),
        ));
        let fid = flow_id_for(6, ip(10, 0, 0, 1), 12345, ip(10, 0, 0, 2), 443);
        let m = idx.match_for(fid, Some(1_002.0));
        assert!(m.matched);
        assert_eq!(m.label_code, LABEL_MALICIOUS);
    }

    #[test]
    fn timed_match_outside_window_returns_unmatched() {
        let mut idx = LabelIndex::new();
        idx.insert_row(row(
            ip(10, 0, 0, 1),
            ip(10, 0, 0, 2),
            12345,
            443,
            6,
            "DDoS",
            None,
            Some(1_000.0),
            Some(1_000_000),
        ));
        let fid = flow_id_for(6, ip(10, 0, 0, 1), 12345, ip(10, 0, 0, 2), 443);
        let m = idx.match_for(fid, Some(5_000.0));
        assert!(!m.matched);
        assert_eq!(idx.attack_name(m.attack_idx), Some(UNMATCHED_ATTACK));
    }

    #[test]
    fn ts_none_falls_back_even_with_timed_present() {
        let mut idx = LabelIndex::new();
        idx.insert_row(row(
            ip(10, 0, 0, 1),
            ip(10, 0, 0, 2),
            12345,
            443,
            6,
            "DDoS",
            None,
            Some(1_000.0),
            Some(1_000_000),
        ));
        let fid = flow_id_for(6, ip(10, 0, 0, 1), 12345, ip(10, 0, 0, 2), 443);
        let m = idx.match_for(fid, None);
        assert!(m.matched);
        assert_eq!(m.label_code, LABEL_MALICIOUS);
    }

    #[test]
    fn attack_idx_zero_is_always_unmatched() {
        let idx = LabelIndex::new();
        assert_eq!(idx.attack_name(0), Some(UNMATCHED_ATTACK));
    }

    #[test]
    fn duration_floor_one_second() {
        let mut idx = LabelIndex::new();
        idx.insert_row(row(
            ip(10, 0, 0, 1),
            ip(10, 0, 0, 2),
            12345,
            443,
            6,
            "DDoS",
            None,
            Some(1_000.0),
            Some(0),
        ));
        let fid = flow_id_for(6, ip(10, 0, 0, 1), 12345, ip(10, 0, 0, 2), 443);
        let m = idx.match_for(fid, Some(1_000.5));
        assert!(m.matched);
    }
}
