#[derive(Debug, Clone)]
pub struct NatTimeoutsDummy {
    pub tcp_established_s: Option<u64>,
    pub udp_s: Option<u64>,
    pub icmp_s: Option<u64>,
}

impl Default for NatTimeoutsDummy {
    fn default() -> Self {
        Self {
            tcp_established_s: Some(24 * 60 * 60),
            udp_s: Some(60),
            icmp_s: Some(30),
        }
    }
}