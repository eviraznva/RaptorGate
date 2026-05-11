use std::time::{Duration, SystemTime, UNIX_EPOCH};

use etherparse::{NetSlice, SlicedPacket, TransportSlice};

use crate::dpi::{DpiContext};

use crate::ml::enums::{
    MlAppProto, MlHttpMethod, MlL4Proto, MlPortClass, MlQtype, MlTlsVersion,
};

use crate::ml::extractors::{
    label_max_len, log1p_f32, normalized_hash_bucket, shannon_entropy, shannon_entropy_str,
};

use crate::ml::flow_stats::FlowStatsSnapshot;

pub const ALPN_HASH_BUCKETS: u32 = 4096;
pub const UA_HASH_BUCKETS: u32 = 8192;
pub const ZONE_PAIR_HASH_BUCKETS: u32 = 256;

#[derive(Debug, Clone, Default, PartialEq)]
pub struct MlFeatureVector {
    // ============ L3/L4 baseline (init_from_packet) ============
    /// Protokół warstwy transportowej. UDP flood vs TCP flood mają różne wzorce.
    pub proto: MlL4Proto,
    /// Wersja IP. IPv6 dark traffic rzadki w prod → anomalia sama w sobie.
    pub ip_ver_v6: bool,
    /// Klasa portu docelowego (well-known/registered/dynamic). Skany często
    /// celują dynamic+well-known równolegle.
    pub dst_port_class: MlPortClass,
    /// log1p(src_port). Wysoki efemeryczny port = klient; niski = reflected.
    pub src_port_log: f32,
    /// log1p(dst_port). Surowy sygnał dla rzadkich portów (C2 na 31337).
    pub dst_port_log: f32,
    /// log1p(payload_bytes). Małe = handshake/beacon, duże = exfil/transfer.
    pub payload_len_log: f32,
    /// log1p(μs od ostatniego pakietu tego src_ip). Regularne = beacon C2.
    pub iat_log: f32,
    /// TTL znormalizowane do [0,1] (dzielone przez 255). OS fingerprint sygnał.
    pub ttl_norm: f32,

    // ============ TCP (set_from_tcp_slice) ============
    /// SYN bez ACK — używany w syn_rate.
    pub tcp_syn: bool,
    pub tcp_ack: bool,
    pub tcp_fin: bool,
    /// RST spike = port scan / connection killed mid-flow.
    pub tcp_rst: bool,
    /// PSH push = interaktywny ruch (SSH shell, stream exfil).
    pub tcp_psh: bool,
    /// log1p(receive_window). Window=0 w handshake = SYN cookie / evasion.
    pub tcp_window_log: f32,

    // ============ Application layer ============
    pub app_proto: MlAppProto,

    // ============ TLS ============
    /// Wersja TLS. TLS 1.0/1.1 wychodzące z klienta = legacy malware / downgrade.
    pub tls_version: MlTlsVersion,
    /// Encrypted ClientHello wykryte — utrudnia SNI-based filtering, sygnał
    /// obejścia DPI.
    pub tls_ech_detected: bool,
    /// Shannon entropy SNI. Wysoka entropia → DGA / tunneling / random subdomain.
    pub sni_entropy: f32,
    pub sni_len: f32,
    /// Hash-bucket ALPN listy znormalizowany do [0,1). Pozwala modelowi uczyć
    /// się par (ALPN, SNI) bez trzymania stringa.
    pub alpn_hash_bucket: f32,

    // ============ HTTP ============
    pub http_method: MlHttpMethod,
    /// Entropia Host headera. DGA → wysoka.
    pub host_entropy: f32,
    /// Hash-bucket User-Agent znormalizowany do [0,1).
    pub ua_hash_bucket: f32,
    /// Entropia znormalizowanej ładunki HTTP. Wysoka = zaszyfrowane/skompresowane
    /// dane w czystym HTTP = exfil/C2.
    pub payload_entropy: f32,

    // ============ DNS ============
    /// Entropia qname. DGA domeny mają entropię >4.0.
    pub qname_entropy: f32,
    pub qname_len: f32,
    /// Długość najdłuższego labela. DNS tunneling upycha dane (label=63 max).
    pub label_max_len: f32,
    pub qtype: MlQtype,
    /// Liczba rekordów w answer section.
    pub answer_count: f32,
    /// DNS rcode (0=OK, 3=NXDOMAIN, itd).
    pub rcode: f32,

    // ============ Context ============
    pub hour_sin: f32,
    pub hour_cos: f32,
    /// Hash-bucket UUID-a zone_pair znormalizowany do [0,1). Pozwala modelowi
    /// uczyć się per-para stref (DMZ→Internal vs Guest→Internet).
    pub zone_pair_bucket: f32,

    /// Ile razy cert pinning się złamał dla (src_ip, domain) w oknie 60s.
    /// Częste failures = MitM detection u klienta → sygnał że intercept
    /// targetuje chronioną aplikację.
    pub pinning_failures_60s: f32,

    // ============ Rolling per-src_ip (FlowStatsAggregator) ============
    /// log1p(unique destination IPs w 60s). Scan fingerprint.
    pub unique_dst_60s_log: f32,
    /// log1p(SYN count / 60). SYN flood signature.
    pub syn_rate_60s_log: f32,
    /// NXDOMAIN / total DNS responses w 60s. DGA miss ratio.
    pub nxdomain_ratio_60s: f32,
    /// log1p(new_flow_count / 60). Worm-style lateral movement.
    pub new_flow_rate_60s_log: f32,
}

impl MlFeatureVector {
    pub fn init_from_packet(&mut self, sliced: &SlicedPacket<'_>, arrival: SystemTime) {
        let (ip_ver_v6, ttl) = match &sliced.net {
            Some(NetSlice::Ipv4(ipv4)) => (false, ipv4.header().ttl()),
            Some(NetSlice::Ipv6(ipv6)) => (true, ipv6.header().hop_limit()),
            _ => (false, 0),
        };
        
        self.ip_ver_v6 = ip_ver_v6;
        self.ttl_norm = ttl as f32 / 255.0;
        
        let (proto, src_port, dst_port, payload_len) = match &sliced.transport {
            Some(TransportSlice::Tcp(tcp)) => (
                MlL4Proto::Tcp,
                tcp.source_port(),
                tcp.destination_port(),
                tcp.payload().len(),
            ),
            Some(TransportSlice::Udp(udp)) => (
                MlL4Proto::Udp,
                udp.source_port(),
                udp.destination_port(),
                udp.payload().len(),
            ),
            Some(TransportSlice::Icmpv4(_)) | Some(TransportSlice::Icmpv6(_)) => {
                (MlL4Proto::Icmp, 0, 0, 0)
            }
            None => (MlL4Proto::Other, 0, 0, 0),
        };
        
        self.proto = proto;
        self.src_port_log = log1p_f32(src_port as f32);
        self.dst_port_log = log1p_f32(dst_port as f32);
        self.dst_port_class = MlPortClass::from_port(dst_port);
        self.payload_len_log = log1p_f32(payload_len as f32);
        
        let secs_today = arrival
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs()
            % 86_400;
        
        let frac = secs_today as f32 / 86_400.0;
        let angle = frac * 2.0 * std::f32::consts::PI;
        
        self.hour_sin = angle.sin();
        self.hour_cos = angle.cos();
    }
    
    pub fn set_from_tcp_slice(&mut self, tcp: &etherparse::TcpSlice<'_>) {
        self.tcp_syn = tcp.syn();
        self.tcp_ack = tcp.ack();
        self.tcp_fin = tcp.fin();
        self.tcp_rst = tcp.rst();
        self.tcp_psh = tcp.psh();
        self.tcp_window_log = log1p_f32(tcp.window_size() as f32);
    }
    
    pub fn set_from_dpi(&mut self, dpi: &DpiContext) {
        if let Some(proto) = dpi.app_proto {
            self.app_proto = MlAppProto::from(proto);
        }
        
        if let Some(v) = dpi.tls_version {
            self.tls_version = MlTlsVersion::from_raw(v);
        }
        
        self.tls_ech_detected = dpi.tls_ech_detected;
        
        if let Some(sni) = dpi.tls_sni.as_deref() {
            self.sni_entropy = shannon_entropy_str(sni);
            self.sni_len = sni.len() as f32;
        }
        
        if let Some(m) = dpi.http_method.as_deref() {
            self.http_method = MlHttpMethod::from_str_case_insensitive(m);
        }
        if let Some(host) = dpi.http_host.as_deref() {
            self.host_entropy = shannon_entropy_str(host);
        }
        if let Some(ua) = dpi.http_user_agent.as_deref() {
            self.ua_hash_bucket = normalized_hash_bucket(ua, UA_HASH_BUCKETS);
        }
        if let Some(payload) = dpi.http_normalized_payload.as_deref() {
            self.payload_entropy = shannon_entropy(payload);
        }
        
        if let Some(qname) = dpi.dns_query_name.as_deref() {
            self.qname_entropy = shannon_entropy_str(qname);
            self.qname_len = qname.len() as f32;
            self.label_max_len = label_max_len(qname) as f32;
        }
        if let Some(qtype) = dpi.dns_query_type {
            self.qtype = MlQtype::from(qtype);
        }
        self.answer_count = dpi.dns_answer_count as f32;
        self.rcode = dpi.dns_rcode as f32;
    }
    
    pub fn set_alpn(&mut self, alpn_joined: &str) {
        self.alpn_hash_bucket = normalized_hash_bucket(alpn_joined, ALPN_HASH_BUCKETS);
    }
    
    pub fn set_zone_pair(&mut self, zone_pair_id: &str) {
        self.zone_pair_bucket = normalized_hash_bucket(zone_pair_id, ZONE_PAIR_HASH_BUCKETS);
    }

    pub fn set_pinning_failures(&mut self, count: u32) {
        self.pinning_failures_60s = count as f32;
    }

    pub fn set_flow_snapshot(&mut self, s: &FlowStatsSnapshot, iat: Duration) {
        self.unique_dst_60s_log = log1p_f32(s.unique_dst_60s as f32);
        self.syn_rate_60s_log = log1p_f32(s.syn_rate_60s);
        self.nxdomain_ratio_60s = s.nxdomain_ratio_60s;
        self.new_flow_rate_60s_log = log1p_f32(s.new_flow_rate_60s);
        self.iat_log = log1p_f32(iat.as_micros() as f32);
    }
    
    pub fn to_f32_array(&self) -> [f32; 38] {
        [
            self.proto.to_f32(),
            if self.ip_ver_v6 { 1.0 } else { 0.0 },
            self.dst_port_class.to_f32(),
            self.src_port_log,
            self.dst_port_log,
            self.payload_len_log,
            self.iat_log,
            self.ttl_norm,
            if self.tcp_syn { 1.0 } else { 0.0 },
            if self.tcp_ack { 1.0 } else { 0.0 },
            if self.tcp_fin { 1.0 } else { 0.0 },
            if self.tcp_rst { 1.0 } else { 0.0 },
            if self.tcp_psh { 1.0 } else { 0.0 },
            self.tcp_window_log,
            self.app_proto.to_f32(),
            self.tls_version.to_f32(),
            if self.tls_ech_detected { 1.0 } else { 0.0 },
            self.sni_entropy,
            self.sni_len,
            self.alpn_hash_bucket,
            self.http_method.to_f32(),
            self.host_entropy,
            self.ua_hash_bucket,
            self.payload_entropy,
            self.qname_entropy,
            self.qname_len,
            self.label_max_len,
            self.qtype.to_f32(),
            self.answer_count,
            self.rcode,
            self.hour_sin,
            self.hour_cos,
            self.zone_pair_bucket,
            self.pinning_failures_60s,
            self.unique_dst_60s_log,
            self.syn_rate_60s_log,
            self.nxdomain_ratio_60s,
            self.new_flow_rate_60s_log,
        ]
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::dpi::AppProto;
    use crate::dpi::parsers::dns::DnsRecordType;

    #[test]
    fn set_from_dpi_tls_populates() {
        let mut v = MlFeatureVector::default();
        let mut dpi = DpiContext::default();
        
        dpi.app_proto = Some(AppProto::Tls);
        dpi.tls_sni = Some("example.com".to_string());
        dpi.tls_version = Some(0x0303);
        v.set_from_dpi(&dpi);

        assert_eq!(v.app_proto, MlAppProto::Tls);
        assert_eq!(v.tls_version, MlTlsVersion::Tls12);
        assert!(v.sni_entropy > 0.0);
        assert_eq!(v.sni_len, 11.0);
    }

    #[test]
    fn set_from_dpi_dga_like_high_entropy() {
        let mut v = MlFeatureVector::default();
        let mut dpi = DpiContext::default();
        dpi.app_proto = Some(AppProto::Dns);
        dpi.dns_query_name = Some("xkjh8f2lqp3rvnzm.net".to_string());
        dpi.dns_query_type = Some(DnsRecordType::A);
        v.set_from_dpi(&dpi);

        assert_eq!(v.qtype, MlQtype::A);
        assert!(v.qname_entropy > 3.0);
        assert_eq!(v.qname_len, 20.0);
    }

    #[test]
    fn init_from_packet_ipv4_empty_when_no_net() {
        let sliced = SlicedPacket {
            link: None,
            link_exts: Default::default(),
            net: None,
            transport: None,
        };
        let mut v = MlFeatureVector::default();
        v.init_from_packet(&sliced, SystemTime::UNIX_EPOCH);
        assert!(!v.ip_ver_v6);
        assert_eq!(v.proto, MlL4Proto::Other);
    }

    #[test]
    fn to_f32_array_stable_length() {
        let v = MlFeatureVector::default();
        assert_eq!(v.to_f32_array().len(), 38);
    }

    #[test]
    fn init_from_packet_tcp_443() {
        use etherparse::PacketBuilder;
        let mut raw = Vec::new();
        PacketBuilder::ethernet2([1, 2, 3, 4, 5, 6], [7, 8, 9, 10, 11, 12])
            .ipv4([10, 0, 0, 1], [10, 0, 0, 2], 64)
            .tcp(54321, 443, 1, 65535)
            .write(&mut raw, b"")
            .unwrap();
        let sliced = SlicedPacket::from_ethernet(&raw).unwrap();
        let mut v = MlFeatureVector::default();
        v.init_from_packet(&sliced, SystemTime::UNIX_EPOCH);
        assert_eq!(v.proto, MlL4Proto::Tcp);
        assert!(!v.ip_ver_v6);
        assert_eq!(v.dst_port_class, MlPortClass::WellKnown);
        assert!((v.ttl_norm - 64.0 / 255.0).abs() < 1e-4);
    }

    #[test]
    fn flow_snapshot_sets_rolling_fields() {
        let mut v = MlFeatureVector::default();
        let snap = FlowStatsSnapshot {
            unique_dst_60s: 10,
            syn_rate_60s: 2.0,
            nxdomain_ratio_60s: 0.25,
            new_flow_rate_60s: 0.5,
        };
        v.set_flow_snapshot(&snap, Duration::from_millis(5));
        assert!(v.unique_dst_60s_log > 0.0);
        assert_eq!(v.nxdomain_ratio_60s, 0.25);
        assert!(v.iat_log > 0.0);
    }
}
