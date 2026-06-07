use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::{Duration, UNIX_EPOCH};

use etherparse::SlicedPacket;
use ngfw::dpi::{DpiClassifier, InspectResult};
use ngfw::ml::feature_vector::MlFeatureVector;
use rayon::prelude::*;

use crate::error::{PcapError, Result};
use crate::flow_id::flow_id_for;
use crate::index::{frame_bytes, prepass, MappedPcap, PcapIndex};
use crate::labels::{LabelIndex, LabelMatch, LABEL_MALICIOUS};
use crate::output::FeatureOutput;
use crate::parse::{is_syn, is_syn_ack};
use crate::stats::FlowStatsAggregator;

const FEATURE_DIM: usize = 38;

static FEATURES_SAMPLE: AtomicUsize = AtomicUsize::new(0);

pub struct BuildOptions {
    pub window_secs: f64,
    pub num_workers: Option<usize>,
    pub thread_name: &'static str,
}

impl Default for BuildOptions {
    fn default() -> Self {
        Self {
            window_secs: 60.0,
            num_workers: None,
            thread_name: "raptorgate-pcap-features",
        }
    }
}

pub fn build_features(
    mapped: &MappedPcap,
    label_index: &LabelIndex,
    classifier: Arc<DpiClassifier>,
    opts: BuildOptions,
) -> Result<FeatureOutput> {
    eprintln!("[raptorgate-pcap] build_features: starting prepass");
    let index = prepass(mapped)?;
    eprintln!(
        "[raptorgate-pcap] build_features: prepass done record_count={} unparsable={} src_ips={}",
        index.record_count,
        index.unparsable,
        index.by_src.len()
    );

    let mut builder = rayon::ThreadPoolBuilder::new().thread_name(move |i| {
        format!("{}-{}", opts.thread_name, i)
    });
    if let Some(n) = opts.num_workers {
        if n > 0 {
            builder = builder.num_threads(n);
        }
    }
    let pool = builder.build().map_err(PcapError::ThreadPool)?;

    let n_workers = pool.current_num_threads();
    let buckets = index.partition(n_workers);
    eprintln!(
        "[raptorgate-pcap] build_features: pool built n_workers={} buckets={}",
        n_workers,
        buckets.len()
    );
    let mapped_ref: &MappedPcap = mapped;

    let per_bucket: Vec<FeatureOutput> = pool.install(|| {
        eprintln!("[raptorgate-pcap] pool.install: dispatching {} buckets", buckets.len());
        let v: Vec<FeatureOutput> = buckets
            .par_iter()
            .map(|bucket| {
                eprintln!(
                    "[raptorgate-pcap] extract_bucket: start bucket size={}",
                    bucket.len()
                );
                extract_bucket(
                    mapped_ref,
                    &index,
                    bucket,
                    label_index,
                    classifier.clone(),
                    opts.window_secs,
                )
            })
            .collect();
        eprintln!("[raptorgate-pcap] pool.install: all buckets returned");
        v
    });
    eprintln!("[raptorgate-pcap] build_features: pool.install returned, merging");

    let out = merge_outputs(per_bucket);
    eprintln!("[raptorgate-pcap] build_features: merged n_rows={}", out.n_rows);
    Ok(out)
}

fn extract_bucket(
    mapped: &MappedPcap,
    index: &PcapIndex,
    bucket: &[std::net::IpAddr],
    label_index: &LabelIndex,
    classifier: Arc<DpiClassifier>,
    window_secs: f64,
) -> FeatureOutput {
    let mut agg = FlowStatsAggregator::new(window_secs);
    let mut out = FeatureOutput::with_capacity(1024);

    for src_ip in bucket {
        let Some(refs) = index.by_src.get(src_ip) else {
            continue;
        };
        for p in refs {
            let Some(frame) = frame_bytes(mapped, p) else {
                continue;
            };
            let Some(sliced) = parse_sliced(mapped.linktype(), frame) else {
                continue;
            };

            let src_ip_pkt = p.src_ip;
            let dst_ip_pkt = p.dst_ip;
            let ip_proto = p.ip_proto;
            let src_port = p.src_port;
            let dst_port = p.dst_port;
            let tcp_flags = p.tcp_flags;

            let snap = agg.snapshot(src_ip_pkt, p.ts);
            let iat = agg.iat_since_last(src_ip_pkt, p.ts);
            let is_new_flow = tcp_flags.map(|f| is_syn(f) || is_syn_ack(f)).unwrap_or(false);
            let is_syn_flag = tcp_flags.map(is_syn).unwrap_or(false);

            agg.observe_packet(src_ip_pkt, dst_ip_pkt, is_syn_flag, is_new_flow, p.ts);

            let mut fv = MlFeatureVector::default();
            let ts_system = UNIX_EPOCH + Duration::from_secs_f64(p.ts.max(0.0));
            fv.init_from_packet(&sliced, ts_system);
            if let Some(etherparse::TransportSlice::Tcp(tcp)) = sliced.transport.as_ref() {
                fv.set_from_tcp_slice(tcp);
            }

            if let InspectResult::Done(ctx) = classifier.inspect_packet(&sliced) {
                fv.set_from_dpi(&ctx);
                if ctx.dns_is_response == Some(true) {
                    let rcode = udp_payload_rcode(&sliced).unwrap_or(0);
                    agg.observe_dns_response(src_ip_pkt, rcode, p.ts);
                }
            }

            let iat_dur = Duration::from_secs_f64(iat);
            let snap_ngfw = ngfw::ml::flow_stats::FlowStatsSnapshot {
                unique_dst_60s: snap.unique_dst_60s,
                syn_rate_60s: snap.syn_rate_60s,
                nxdomain_ratio_60s: snap.nxdomain_ratio_60s,
                new_flow_rate_60s: snap.new_flow_rate_60s,
            };
            fv.set_flow_snapshot(&snap_ngfw, iat_dur);

            let row = fv.to_f32_array();
            let flow_id = flow_id_for(ip_proto, src_ip_pkt, src_port, dst_ip_pkt, dst_port);
            let m = label_index.match_for(flow_id, Some(p.ts));
            if std::env::var("RG_FEATURES_DEBUG").is_ok() {
                let n = FEATURES_SAMPLE.fetch_add(1, Ordering::Relaxed);
                if n < 5 {
                    eprintln!(
                        "[features.rs] sample n={} flow_id={:#x} ts={} match.matched={} attack_idx={} label_code={} src={} dst={} sp={} dp={} proto={}",
                        n, flow_id, p.ts, m.matched, m.attack_idx, m.label_code,
                        src_ip_pkt, dst_ip_pkt, src_port, dst_port, ip_proto
                    );
                }
            }
            push_row(&mut out, &row, &m, flow_id, &m);
        }
    }

    out
}

fn push_row(out: &mut FeatureOutput, row: &[f32; FEATURE_DIM], _m: &LabelMatch, flow_id: u64, m: &LabelMatch) {
    out.features.extend_from_slice(row);
    out.label.push(if m.label_code == LABEL_MALICIOUS { 1 } else { 0 });
    let idx = if m.matched && m.attack_idx > 0 {
        m.attack_idx as i32
    } else {
        -1
    };
    out.attack_idx.push(idx);
    out.matched.push(m.matched);
    out.flow_id.push(flow_id);
    out.n_rows += 1;
    if out.n_rows % 1_000_000 == 0 {
        let thread = std::thread::current();
        let thread_name = thread.name().unwrap_or("raptorgate-pcap-worker");
        eprintln!("[raptorgate-pcap] {thread_name}: processed {} rows", out.n_rows);
    }
}

fn merge_outputs(parts: Vec<FeatureOutput>) -> FeatureOutput {
    let total_rows: usize = parts.iter().map(|p| p.n_rows).sum();
    let mut out = FeatureOutput::with_capacity(total_rows);
    for p in parts {
        out.features.extend(p.features);
        out.label.extend(p.label);
        out.attack_idx.extend(p.attack_idx);
        out.matched.extend(p.matched);
        out.flow_id.extend(p.flow_id);
        out.n_rows += p.n_rows;
    }
    out
}

fn parse_sliced<'a>(linktype: u32, frame: &'a [u8]) -> Option<SlicedPacket<'a>> {
    match linktype {
        1 => SlicedPacket::from_ethernet(frame).ok(),
        113 => SlicedPacket::from_linux_sll(frame).ok(),
        101 | 12 | 228 | 229 => SlicedPacket::from_ip(frame).ok(),
        _ => None,
    }
}

// `DpiContext::dns_rcode` is not populated by the data plane's
// `dns_to_dpi_context`. Re-parse the DNS header locally so the
// FlowStatsAggregator sees the real rcode.
fn udp_payload_rcode(sliced: &SlicedPacket<'_>) -> Option<u16> {
    let udp = match sliced.transport.as_ref()? {
        etherparse::TransportSlice::Udp(u) => u,
        _ => return None,
    };
    let payload = udp.payload();
    if payload.len() < 4 {
        return None;
    }
    Some((payload[3] & 0x0f) as u16)
}
