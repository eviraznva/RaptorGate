from raptorgate_ml.flow_stats import FlowStatsAggregator


SRC = "10.0.0.1"


def test_syn_rate_counts_in_window():
    agg = FlowStatsAggregator(window_secs=60.0)
    t0 = 1000.0
    for i in range(10):
        agg.observe_packet(SRC, "192.168.1.1", True, True, t0 + i * 0.01)
    snap = agg.snapshot(SRC, t0 + 0.1)
    assert abs(snap.syn_rate_60s - 10.0 / 60.0) < 1e-3


def test_nxdomain_ratio():
    agg = FlowStatsAggregator(window_secs=60.0)
    now = 5000.0
    for _ in range(7):
        agg.observe_dns_response(SRC, 0, now)
    for _ in range(3):
        agg.observe_dns_response(SRC, 3, now)
    snap = agg.snapshot(SRC, now)
    assert abs(snap.nxdomain_ratio_60s - 0.3) < 1e-3


def test_unique_dst_count():
    agg = FlowStatsAggregator(window_secs=60.0)
    now = 1000.0
    for i in range(1, 6):
        agg.observe_packet(SRC, f"192.168.1.{i}", False, False, now)
    agg.observe_packet(SRC, "192.168.1.3", False, False, now)
    snap = agg.snapshot(SRC, now)
    assert snap.unique_dst_60s == 5


def test_iat_measures_since_last():
    agg = FlowStatsAggregator(window_secs=60.0)
    now = 1000.0
    agg.observe_packet(SRC, "10.0.0.2", False, False, now)
    iat = agg.iat_since_last(SRC, now + 0.25)
    assert 0.24 <= iat <= 0.26
