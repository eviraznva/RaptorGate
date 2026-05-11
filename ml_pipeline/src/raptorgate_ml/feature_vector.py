import math
from dataclasses import dataclass

import numpy as np

from raptorgate_ml.dpi import DpiContext
from raptorgate_ml.enums import (
    MlAppProto,
    MlHttpMethod,
    MlL4Proto,
    MlPortClass,
    MlQtype,
    MlTlsVersion,
)
from raptorgate_ml.extractors import (
    ALPN_HASH_BUCKETS,
    UA_HASH_BUCKETS,
    ZONE_PAIR_HASH_BUCKETS,
    label_max_len,
    log1p_f32,
    normalized_hash_bucket,
    shannon_entropy,
    shannon_entropy_str,
)
from raptorgate_ml.flow_stats import FlowStatsSnapshot

FIELD_NAMES: list[str] = [
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
]


@dataclass
class MlFeatureVector:
    proto: MlL4Proto = MlL4Proto.Other
    ip_ver_v6: bool = False
    dst_port_class: MlPortClass = MlPortClass.Unknown
    src_port_log: float = 0.0
    dst_port_log: float = 0.0
    payload_len_log: float = 0.0
    iat_log: float = 0.0
    ttl_norm: float = 0.0

    tcp_syn: bool = False
    tcp_ack: bool = False
    tcp_fin: bool = False
    tcp_rst: bool = False
    tcp_psh: bool = False
    tcp_window_log: float = 0.0

    app_proto: MlAppProto = MlAppProto.Unknown

    tls_version: MlTlsVersion = MlTlsVersion.Unknown
    tls_ech_detected: bool = False
    sni_entropy: float = 0.0
    sni_len: float = 0.0
    alpn_hash_bucket: float = 0.0

    http_method: MlHttpMethod = MlHttpMethod.Null
    host_entropy: float = 0.0
    ua_hash_bucket: float = 0.0
    payload_entropy: float = 0.0

    qname_entropy: float = 0.0
    qname_len: float = 0.0
    label_max_len: float = 0.0
    qtype: MlQtype = MlQtype.Null
    answer_count: float = 0.0
    rcode: float = 0.0

    hour_sin: float = 0.0
    hour_cos: float = 0.0
    zone_pair_bucket: float = 0.0

    pinning_failures_60s: float = 0.0

    unique_dst_60s_log: float = 0.0
    syn_rate_60s_log: float = 0.0
    nxdomain_ratio_60s: float = 0.0
    new_flow_rate_60s_log: float = 0.0

    def init_from_packet(
        self,
        ip_version: int,
        ip_proto: int,
        ttl: int,
        src_port: int,
        dst_port: int,
        payload_len: int,
        arrival_ts: float,
    ) -> None:
        self.ip_ver_v6 = ip_version == 6
        self.ttl_norm = (ttl / 255.0) if ttl else 0.0
        self.proto = MlL4Proto.from_ip_proto(ip_proto)
        self.src_port_log = log1p_f32(float(src_port))
        self.dst_port_log = log1p_f32(float(dst_port))
        self.dst_port_class = MlPortClass.from_port(dst_port)
        self.payload_len_log = log1p_f32(float(payload_len))

        secs_today = int(arrival_ts) % 86_400
        angle = (secs_today / 86_400.0) * 2.0 * math.pi
        self.hour_sin = math.sin(angle)
        self.hour_cos = math.cos(angle)

    def set_from_tcp(
        self,
        syn: bool,
        ack: bool,
        fin: bool,
        rst: bool,
        psh: bool,
        window: int,
    ) -> None:
        self.tcp_syn = syn
        self.tcp_ack = ack
        self.tcp_fin = fin
        self.tcp_rst = rst
        self.tcp_psh = psh
        self.tcp_window_log = log1p_f32(float(window))

    def set_from_dpi(self, dpi: DpiContext) -> None:
        if dpi.app_proto is not None:
            self.app_proto = MlAppProto(dpi.app_proto)

        if dpi.tls_version is not None:
            self.tls_version = MlTlsVersion.from_raw(dpi.tls_version)

        self.tls_ech_detected = dpi.tls_ech_detected

        if dpi.tls_sni:
            self.sni_entropy = shannon_entropy_str(dpi.tls_sni)
            self.sni_len = float(len(dpi.tls_sni))

        if dpi.tls_alpn:
            self.set_alpn(",".join(dpi.tls_alpn))

        if dpi.http_method:
            self.http_method = MlHttpMethod.from_str_case_insensitive(dpi.http_method)
        if dpi.http_host:
            self.host_entropy = shannon_entropy_str(dpi.http_host)
        if dpi.http_user_agent:
            self.ua_hash_bucket = normalized_hash_bucket(dpi.http_user_agent, UA_HASH_BUCKETS)
        if dpi.http_normalized_payload:
            self.payload_entropy = shannon_entropy(dpi.http_normalized_payload)

        if dpi.dns_query_name:
            self.qname_entropy = shannon_entropy_str(dpi.dns_query_name)
            self.qname_len = float(len(dpi.dns_query_name))
            self.label_max_len = float(label_max_len(dpi.dns_query_name))
        if dpi.dns_query_type_code is not None:
            self.qtype = MlQtype.from_dns_type_code(dpi.dns_query_type_code)
        self.answer_count = float(dpi.dns_answer_count)
        self.rcode = float(dpi.dns_rcode)

    def set_alpn(self, alpn_joined: str) -> None:
        self.alpn_hash_bucket = normalized_hash_bucket(alpn_joined, ALPN_HASH_BUCKETS)

    def set_zone_pair(self, zone_pair_id: str) -> None:
        self.zone_pair_bucket = normalized_hash_bucket(zone_pair_id, ZONE_PAIR_HASH_BUCKETS)

    def set_pinning_failures(self, count: int) -> None:
        self.pinning_failures_60s = float(count)

    def set_flow_snapshot(self, snap: FlowStatsSnapshot, iat_seconds: float) -> None:
        self.unique_dst_60s_log = log1p_f32(float(snap.unique_dst_60s))
        self.syn_rate_60s_log = log1p_f32(snap.syn_rate_60s)
        self.nxdomain_ratio_60s = snap.nxdomain_ratio_60s
        self.new_flow_rate_60s_log = log1p_f32(float(snap.new_flow_rate_60s))
        self.iat_log = log1p_f32(iat_seconds * 1_000_000.0)

    def to_array(self) -> np.ndarray:
        return np.array(
            [
                float(self.proto.value),
                1.0 if self.ip_ver_v6 else 0.0,
                float(self.dst_port_class.value),
                self.src_port_log,
                self.dst_port_log,
                self.payload_len_log,
                self.iat_log,
                self.ttl_norm,
                1.0 if self.tcp_syn else 0.0,
                1.0 if self.tcp_ack else 0.0,
                1.0 if self.tcp_fin else 0.0,
                1.0 if self.tcp_rst else 0.0,
                1.0 if self.tcp_psh else 0.0,
                self.tcp_window_log,
                float(self.app_proto.value),
                float(self.tls_version.value),
                1.0 if self.tls_ech_detected else 0.0,
                self.sni_entropy,
                self.sni_len,
                self.alpn_hash_bucket,
                float(self.http_method.value),
                self.host_entropy,
                self.ua_hash_bucket,
                self.payload_entropy,
                self.qname_entropy,
                self.qname_len,
                self.label_max_len,
                float(self.qtype.value),
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
            ],
            dtype=np.float32,
        )
