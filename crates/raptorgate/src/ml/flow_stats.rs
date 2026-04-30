use std::net::IpAddr;
use std::time::{Duration, Instant};
use std::collections::{HashMap, VecDeque};

use dashmap::DashMap;

#[derive(Debug, Clone, Default)]
pub struct FlowStatsSnapshot {
    pub unique_dst_60s: u32,
    pub syn_rate_60s: f32,
    pub nxdomain_ratio_60s: f32,
    pub new_flow_rate_60s: f32,
}

#[derive(Debug)]
struct SrcStats {
    last_seen: Instant,
    last_packet_time: Option<Instant>,
    syn_events: VecDeque<Instant>,
    new_flow_events: VecDeque<Instant>,
    dst_ips: HashMap<IpAddr, Instant>,
    dns_total_events: VecDeque<Instant>,
    dns_nxdomain_events: VecDeque<Instant>,
}

impl SrcStats {
    fn new(now: Instant) -> Self {
        Self {
            last_seen: now,
            last_packet_time: None,
            syn_events: VecDeque::new(),
            new_flow_events: VecDeque::new(),
            dst_ips: HashMap::new(),
            dns_total_events: VecDeque::new(),
            dns_nxdomain_events: VecDeque::new(),
        }
    }

    fn trim(&mut self, now: Instant, window: Duration) {
        let cutoff = now.checked_sub(window).unwrap_or(now);
        
        while self.syn_events.front().map_or(false, |t| *t < cutoff) {
            self.syn_events.pop_front();
        }
        
        while self.new_flow_events.front().map_or(false, |t| *t < cutoff) {
            self.new_flow_events.pop_front();
        }
        
        while self.dns_total_events.front().map_or(false, |t| *t < cutoff) {
            self.dns_total_events.pop_front();
        }
        
        while self.dns_nxdomain_events.front().map_or(false, |t| *t < cutoff) {
            self.dns_nxdomain_events.pop_front();
        }
        
        self.dst_ips.retain(|_, seen| *seen >= cutoff);
    }
}

pub struct FlowStatsAggregator {
    per_src: DashMap<IpAddr, SrcStats>,
    window: Duration,
}

impl FlowStatsAggregator {
    pub fn new(window: Duration) -> Self {
        Self {
            per_src: DashMap::new(),
            window,
        }
    }

    pub fn window(&self) -> Duration {
        self.window
    }
    
    pub fn observe_packet(
        &self,
        src: IpAddr,
        dst: IpAddr,
        is_syn: bool,
        is_new_flow: bool,
        now: Instant,
    ) {
        let mut entry = self
            .per_src
            .entry(src)
            .or_insert_with(|| SrcStats::new(now));
        
        entry.last_seen = now;
        entry.last_packet_time = Some(now);
        
        entry.dst_ips.insert(dst, now);
        
        if is_syn {
            entry.syn_events.push_back(now);
        }
        
        if is_new_flow {
            entry.new_flow_events.push_back(now);
        }
        
        entry.trim(now, self.window);
    }
    
    pub fn observe_dns_response(&self, src: IpAddr, rcode: u16, now: Instant) {
        let mut entry = self
            .per_src
            .entry(src)
            .or_insert_with(|| SrcStats::new(now));
        
        entry.last_seen = now;
        entry.dns_total_events.push_back(now);
        
        if rcode == 3 {
            entry.dns_nxdomain_events.push_back(now);
        }
        
        entry.trim(now, self.window);
    }
    
    pub fn iat_since_last(&self, src: IpAddr, now: Instant) -> Duration {
        self.per_src
            .get(&src)
            .and_then(|e| e.last_packet_time.map(|t| now.duration_since(t)))
            .unwrap_or_default()
    }

    pub fn snapshot(&self, src: IpAddr, now: Instant) -> FlowStatsSnapshot {
        let Some(entry) = self.per_src.get(&src) else {
            return FlowStatsSnapshot::default();
        };
        
        let cutoff = now.checked_sub(self.window).unwrap_or(now);
        let secs = self.window.as_secs_f32().max(1.0);

        let syn_count = entry.syn_events.iter().filter(|t| **t >= cutoff).count() as f32;
        
        let new_flow_count = entry
            .new_flow_events
            .iter()
            .filter(|t| **t >= cutoff)
            .count() as f32;
        
        let unique_dst = entry
            .dst_ips
            .iter()
            .filter(|(_, seen)| **seen >= cutoff)
            .count() as u32;
        
        let dns_total = entry
            .dns_total_events
            .iter()
            .filter(|t| **t >= cutoff)
            .count() as f32;
        
        let dns_nx = entry
            .dns_nxdomain_events
            .iter()
            .filter(|t| **t >= cutoff)
            .count() as f32;

        let nxdomain_ratio = if dns_total > 0.0 {
            dns_nx / dns_total
        } else {
            0.0
        };

        FlowStatsSnapshot {
            unique_dst_60s: unique_dst,
            syn_rate_60s: syn_count / secs,
            nxdomain_ratio_60s: nxdomain_ratio,
            new_flow_rate_60s: new_flow_count / secs,
        }
    }
    
    pub fn gc(&self, now: Instant) {
        let dead_cutoff = now
            .checked_sub(self.window.saturating_mul(2))
            .unwrap_or(now);
        
        self.per_src.retain(|_, stats| stats.last_seen >= dead_cutoff);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::Ipv4Addr;

    fn src() -> IpAddr {
        IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1))
    }

    fn dst(n: u8) -> IpAddr {
        IpAddr::V4(Ipv4Addr::new(192, 168, 1, n))
    }

    #[test]
    fn syn_rate_counts_in_window() {
        let agg = FlowStatsAggregator::new(Duration::from_secs(60));
        let now = Instant::now();
        for i in 0..10 {
            agg.observe_packet(src(), dst(1), true, true, now + Duration::from_millis(i * 10));
        }
        let snap = agg.snapshot(src(), now + Duration::from_millis(100));
        assert!((snap.syn_rate_60s - 10.0 / 60.0).abs() < 1e-3);
    }

    #[test]
    fn nxdomain_ratio() {
        let agg = FlowStatsAggregator::new(Duration::from_secs(60));
        let now = Instant::now();
        for _ in 0..7 {
            agg.observe_dns_response(src(), 0, now);
        }
        for _ in 0..3 {
            agg.observe_dns_response(src(), 3, now);
        }
        let snap = agg.snapshot(src(), now);
        assert!((snap.nxdomain_ratio_60s - 0.3).abs() < 1e-3);
    }

    #[test]
    fn unique_dst_count() {
        let agg = FlowStatsAggregator::new(Duration::from_secs(60));
        let now = Instant::now();
        for i in 1..=5 {
            agg.observe_packet(src(), dst(i), false, false, now);
        }
        // Duplikat
        agg.observe_packet(src(), dst(3), false, false, now);
        let snap = agg.snapshot(src(), now);
        assert_eq!(snap.unique_dst_60s, 5);
    }

    #[test]
    fn iat_measures_since_last() {
        let agg = FlowStatsAggregator::new(Duration::from_secs(60));
        let now = Instant::now();
        agg.observe_packet(src(), dst(1), false, false, now);
        let later = now + Duration::from_millis(250);
        let iat = agg.iat_since_last(src(), later);
        assert!(iat >= Duration::from_millis(240) && iat <= Duration::from_millis(260));
    }

    #[test]
    fn gc_drops_stale_entries() {
        let agg = FlowStatsAggregator::new(Duration::from_secs(60));
        let t0 = Instant::now();
        agg.observe_packet(src(), dst(1), false, false, t0);
        let future = t0 + Duration::from_secs(300);
        agg.gc(future);
        assert!(agg.per_src.get(&src()).is_none());
    }
}
