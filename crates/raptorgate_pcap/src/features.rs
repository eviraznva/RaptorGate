use std::sync::Arc;
use std::time::{Duration, UNIX_EPOCH};

use etherparse::SlicedPacket;
use ngfw::dpi::{DpiClassifier, InspectResult};
use ngfw::ml::feature_vector::MlFeatureVector;
use rayon::prelude::*;

use crate::error::{PcapError, Result};
use crate::flow_id::flow_id_for;
use crate::index::{packet_bytes, prepass, MappedPcap, PcapIndex};
use crate::labels::{LabelIndex, LabelMatch, LABEL_MALICIOUS};
use crate::output::FeatureOutput;
use crate::parse::{is_syn, is_syn_ack};
use crate::stats::FlowStatsAggregator;

const FEATURE_DIM: usize = 38;

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
    let index = prepass(mapped)?;

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
    let mapped_ref: &MappedPcap = mapped;

    let per_bucket: Vec<FeatureOutput> = pool.install(|| {
        buckets
            .par_iter()
            .map(|bucket| {
                extract_bucket(
                    mapped_ref,
                    &index,
                    bucket,
                    label_index,
                    classifier.clone(),
                    opts.window_secs,
                )
            })
            .collect()
    });

    Ok(merge_outputs(per_bucket))
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
        for r in refs {
            let Some(frame) = packet_bytes(mapped, r) else {
                continue;
            };
            let Some(sliced) = parse_sliced(mapped.linktype(), frame) else {
                continue;
            };

            let src_ip_pkt = match sliced.net.as_ref() {
                Some(etherparse::NetSlice::Ipv4(v4)) => std::net::IpAddr::V4(v4.header().source_addr()),
                Some(etherparse::NetSlice::Ipv6(v6)) => std::net::IpAddr::V6(v6.header().source_addr()),
                _ => continue,
            };
            let dst_ip_pkt = match sliced.net.as_ref() {
                Some(etherparse::NetSlice::Ipv4(v4)) => std::net::IpAddr::V4(v4.header().destination_addr()),
                Some(etherparse::NetSlice::Ipv6(v6)) => std::net::IpAddr::V6(v6.header().destination_addr()),
                _ => continue,
            };
            let ip_proto = match sliced.net.as_ref() {
                Some(etherparse::NetSlice::Ipv4(v4)) => v4.header().protocol().0,
                Some(etherparse::NetSlice::Ipv6(v6)) => v6.header().next_header().0,
                _ => continue,
            };
            let (src_port, dst_port, tcp_flags) = match sliced.transport.as_ref() {
                Some(etherparse::TransportSlice::Tcp(t)) => {
                    let mut flags = 0u8;
                    if t.syn() { flags |= 0x02; }
                    if t.ack() { flags |= 0x10; }
                    if t.fin() { flags |= 0x01; }
                    if t.rst() { flags |= 0x04; }
                    if t.psh() { flags |= 0x08; }
                    if t.urg() { flags |= 0x20; }
                    if t.ece() { flags |= 0x40; }
                    if t.cwr() { flags |= 0x80; }
                    (t.source_port(), t.destination_port(), Some(flags))
                }
                Some(etherparse::TransportSlice::Udp(u)) => {
                    (u.source_port(), u.destination_port(), None)
                }
                _ => (0, 0, None),
            };

            let snap = agg.snapshot(*src_ip, r.ts);
            let iat = agg.iat_since_last(*src_ip, r.ts);
            let is_new_flow = tcp_flags.map(|f| is_syn(f) || is_syn_ack(f)).unwrap_or(false);
            let is_syn_flag = tcp_flags.map(is_syn).unwrap_or(false);

            agg.observe_packet(src_ip_pkt, dst_ip_pkt, is_syn_flag, is_new_flow, r.ts);

            let mut fv = MlFeatureVector::default();
            let ts_system = UNIX_EPOCH + Duration::from_secs_f64(r.ts.max(0.0));
            fv.init_from_packet(&sliced, ts_system);
            if let Some(etherparse::TransportSlice::Tcp(tcp)) = sliced.transport.as_ref() {
                fv.set_from_tcp_slice(tcp);
            }

            if let InspectResult::Done(ctx) = classifier.inspect_packet(&sliced) {
                fv.set_from_dpi(&ctx);
                if ctx.dns_is_response == Some(true) {
                    let rcode = udp_payload_rcode(&sliced).unwrap_or(0);
                    agg.observe_dns_response(src_ip_pkt, rcode, r.ts);
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
            let m = label_index.match_for(flow_id, Some(r.ts));
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
