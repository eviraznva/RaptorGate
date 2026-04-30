from collections import deque
from dataclasses import dataclass, field


@dataclass
class FlowStatsSnapshot:
    unique_dst_60s: int = 0
    syn_rate_60s: float = 0.0
    nxdomain_ratio_60s: float = 0.0
    new_flow_rate_60s: float = 0.0


@dataclass
class _SrcStats:
    last_packet_time: float | None = None
    syn_events: deque = field(default_factory=deque)
    new_flow_events: deque = field(default_factory=deque)
    dst_ips: dict = field(default_factory=dict)
    dns_total_events: deque = field(default_factory=deque)
    dns_nxdomain_events: deque = field(default_factory=deque)

    def trim(self, now: float, window: float) -> None:
        cutoff = now - window
        for dq in (
            self.syn_events,
            self.new_flow_events,
            self.dns_total_events,
            self.dns_nxdomain_events,
        ):
            while dq and dq[0] < cutoff:
                dq.popleft()
        self.dst_ips = {ip: seen for ip, seen in self.dst_ips.items() if seen >= cutoff}


class FlowStatsAggregator:
    def __init__(self, window_secs: float = 60.0) -> None:
        self._window = window_secs
        self._per_src: dict[str, _SrcStats] = {}

    @property
    def window(self) -> float:
        return self._window

    def _entry(self, src: str) -> _SrcStats:
        e = self._per_src.get(src)
        if e is None:
            e = _SrcStats()
            self._per_src[src] = e
        return e

    def observe_packet(
        self,
        src: str,
        dst: str,
        is_syn: bool,
        is_new_flow: bool,
        now: float,
    ) -> None:
        e = self._entry(src)
        e.last_packet_time = now
        e.dst_ips[dst] = now
        if is_syn:
            e.syn_events.append(now)
        if is_new_flow:
            e.new_flow_events.append(now)
        e.trim(now, self._window)

    def observe_dns_response(self, src: str, rcode: int, now: float) -> None:
        e = self._entry(src)
        e.dns_total_events.append(now)
        if rcode == 3:
            e.dns_nxdomain_events.append(now)
        e.trim(now, self._window)

    def iat_since_last(self, src: str, now: float) -> float:
        e = self._per_src.get(src)
        if e is None or e.last_packet_time is None:
            return 0.0
        return max(0.0, now - e.last_packet_time)

    def snapshot(self, src: str, now: float) -> FlowStatsSnapshot:
        e = self._per_src.get(src)
        if e is None:
            return FlowStatsSnapshot()
        cutoff = now - self._window
        secs = max(self._window, 1.0)

        syn_count = sum(1 for t in e.syn_events if t >= cutoff)
        new_flow_count = sum(1 for t in e.new_flow_events if t >= cutoff)
        unique_dst = sum(1 for seen in e.dst_ips.values() if seen >= cutoff)
        dns_total = sum(1 for t in e.dns_total_events if t >= cutoff)
        dns_nx = sum(1 for t in e.dns_nxdomain_events if t >= cutoff)

        nx_ratio = (dns_nx / dns_total) if dns_total > 0 else 0.0

        return FlowStatsSnapshot(
            unique_dst_60s=unique_dst,
            syn_rate_60s=syn_count / secs,
            nxdomain_ratio_60s=nx_ratio,
            new_flow_rate_60s=new_flow_count / secs,
        )
