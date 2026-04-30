import numpy as np

from raptorgate_ml.feature_vector import FIELD_NAMES, MlFeatureVector
from raptorgate_ml.flow_stats import FlowStatsSnapshot


EXPECTED_ORDER = [
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


def test_array_length_is_38():
    fv = MlFeatureVector()
    arr = fv.to_array()
    assert arr.shape == (38,)
    assert arr.dtype == np.float32


def test_field_names_length_and_order():
    assert len(FIELD_NAMES) == 38
    assert FIELD_NAMES == EXPECTED_ORDER


def test_init_from_packet_tcp_443():
    fv = MlFeatureVector()
    fv.init_from_packet(
        ip_version=4,
        ip_proto=6,
        ttl=64,
        src_port=54321,
        dst_port=443,
        payload_len=100,
        arrival_ts=0.0,
    )
    assert fv.proto.name == "Tcp"
    assert fv.ip_ver_v6 is False
    assert fv.ttl_norm == 64.0 / 255.0
    assert fv.dst_port_class.name == "WellKnown"


def test_flow_snapshot_sets_rolling_fields():
    fv = MlFeatureVector()
    snap = FlowStatsSnapshot(
        unique_dst_60s=3,
        syn_rate_60s=5.0,
        nxdomain_ratio_60s=0.25,
        new_flow_rate_60s=2.0,
    )
    fv.set_flow_snapshot(snap, iat_seconds=0.0)
    assert fv.unique_dst_60s_log > 0.0
    assert fv.syn_rate_60s_log > 0.0
    assert fv.nxdomain_ratio_60s == 0.25
    assert fv.new_flow_rate_60s_log > 0.0


def test_array_preserves_field_order():
    fv = MlFeatureVector()
    fv.sni_len = 17.0
    fv.qname_len = 42.0
    arr = fv.to_array()
    assert arr[FIELD_NAMES.index("sni_len")] == 17.0
    assert arr[FIELD_NAMES.index("qname_len")] == 42.0
