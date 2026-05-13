use std::future::Future;
use std::sync::Arc;

use ngfw::events::{EventCapture, EventPredicate, WaitForSubsequenceError};
use thiserror::Error;

use crate::{
    expect_events, EventKind, OutcomeMismatch, PipelineOutcome, ProcessOutputAssertExt, TestDaemon,
};

pub(crate) struct SendStep {
    pub(crate) raw: Vec<u8>,
    pub(crate) iface: Arc<str>,
    pub(crate) expect_packet: Option<PipelineOutcome>,
}

pub(crate) struct ScenarioPlan {
    pub(crate) sends: Vec<SendStep>,
    pub(crate) event_expectations: Vec<EventPredicate>,
}

#[derive(Debug, Error)]
pub enum ScenarioRunError {
    #[error("expect_packet called before any send")]
    ExpectPacketWithoutSend,
    #[error("packet outcome at send index {send_index}: {source}")]
    PacketOutcome {
        send_index: usize,
        #[source]
        source: OutcomeMismatch,
    },
    #[error(transparent)]
    Events(#[from] WaitForSubsequenceError),
}

pub(crate) async fn execute_scenario_plan(
    plan: ScenarioPlan,
    daemon: &TestDaemon,
    capture: &Arc<EventCapture>,
) -> Result<(), ScenarioRunError> {
    capture.clear();
    capture.set_fence(std::time::SystemTime::now());
    tokio::time::sleep(crate::FENCE_SETTLE).await;

    let ScenarioPlan {
        sends,
        event_expectations: preds,
    } = plan;

    for (send_index, step) in sends.into_iter().enumerate() {
        let out = Box::pin(daemon.process_raw(step.raw, step.iface)).await;
        if let Some(exp) = step.expect_packet {
            out.assert_outcome(exp).map_err(|source| ScenarioRunError::PacketOutcome {
                send_index,
                source,
            })?;
        }
    }

    if !preds.is_empty() {
        capture.wait_for_subsequence(&preds).await?;
    }

    Ok(())
}

pub struct PacketsScenario {
    default_iface: Arc<str>,
    plan: ScenarioPlan,
    dangling_packet_expect: bool,
}

impl PacketsScenario {
    pub fn new() -> Self {
        Self {
            default_iface: Arc::from("eth1"),
            plan: ScenarioPlan {
                sends: Vec::new(),
                event_expectations: Vec::new(),
            },
            dangling_packet_expect: false,
        }
    }

    pub fn on_iface(mut self, iface: impl Into<Arc<str>>) -> Self {
        self.default_iface = iface.into();
        self
    }

    pub fn send(mut self, raw: Vec<u8>) -> Self {
        self.dangling_packet_expect = false;
        self.plan.sends.push(SendStep {
            raw,
            iface: self.default_iface.clone(),
            expect_packet: None,
        });
        self
    }

    pub fn expect_packet(mut self, expected: PipelineOutcome) -> Self {
        if let Some(last) = self.plan.sends.last_mut() {
            last.expect_packet = Some(expected);
            self.dangling_packet_expect = false;
        } else {
            self.dangling_packet_expect = true;
        }
        self
    }

    pub fn expect_event(mut self, pred: EventPredicate) -> Self {
        self.plan.event_expectations.push(pred);
        self
    }

    /// Clears `capture`, sets a new fence, runs sends, then checks packet expectations and (if any) event subsequence on `capture`.
    /// When running multiple tests in parallel, acquire [`crate::event_capture_concurrency_mutex`] before [`set_event_capture`] for the same `capture` instance this run uses.
    pub async fn run(
        self,
        daemon: &TestDaemon,
        capture: &Arc<EventCapture>,
    ) -> Result<(), ScenarioRunError> {
        if self.dangling_packet_expect {
            return Err(ScenarioRunError::ExpectPacketWithoutSend);
        }
        Box::pin(execute_scenario_plan(self.plan, daemon, capture)).await
    }
}

pub fn packets() -> PacketsScenario {
    PacketsScenario::new()
}

#[derive(Clone, Copy, Debug)]
pub struct SocketV4 {
    pub ip: [u8; 4],
    pub port: u16,
}

#[derive(Clone, Copy, Debug)]
pub struct TcpSessionV4 {
    pub client: SocketV4,
    pub server: SocketV4,
    pub client_isn: u32,
    pub server_isn: u32,
    pub window: u16,
}

impl TcpSessionV4 {
    pub fn new(client: SocketV4, server: SocketV4) -> Self {
        Self {
            client,
            server,
            client_isn: 1000,
            server_isn: 2000,
            window: 5840,
        }
    }

    pub fn with_isns(mut self, client: u32, server: u32) -> Self {
        self.client_isn = client;
        self.server_isn = server;
        self
    }

    pub fn with_window(mut self, window: u16) -> Self {
        self.window = window;
        self
    }

    fn write_tcp_eth<F>(src: [u8; 4], dst: [u8; 4], sport: u16, dport: u16, seq: u32, win: u16, f: F) -> Vec<u8>
    where
        F: FnOnce(
            etherparse::PacketBuilderStep<etherparse::TcpHeader>,
        ) -> etherparse::PacketBuilderStep<etherparse::TcpHeader>,
    {
        let payload = b"";
        let b = etherparse::PacketBuilder::ethernet2([0; 6], [0; 6])
            .ipv4(src, dst, 64)
            .tcp(sport, dport, seq, win);
        let b = f(b);
        let mut buf = Vec::with_capacity(b.size(payload.len()));
        b.write(&mut buf, payload).unwrap();
        buf
    }

    pub fn syn_from_client(&self) -> Vec<u8> {
        Self::write_tcp_eth(
            self.client.ip,
            self.server.ip,
            self.client.port,
            self.server.port,
            self.client_isn,
            self.window,
            |b| b.syn(),
        )
    }

    pub fn syn_ack_from_server(&self) -> Vec<u8> {
        Self::write_tcp_eth(
            self.server.ip,
            self.client.ip,
            self.server.port,
            self.client.port,
            self.server_isn,
            self.window,
            |b| b.syn().ack(self.client_isn.wrapping_add(1)),
        )
    }

    pub fn ack_from_client(&self) -> Vec<u8> {
        Self::write_tcp_eth(
            self.client.ip,
            self.server.ip,
            self.client.port,
            self.server.port,
            self.client_isn.wrapping_add(1),
            self.window,
            |b| b.ack(self.server_isn.wrapping_add(1)),
        )
    }

    pub fn client_psh_ack_to_server(&self, seq: u32, ack: u32, payload: &[u8]) -> Vec<u8> {
        let b = etherparse::PacketBuilder::ethernet2([0; 6], [0; 6])
            .ipv4(self.client.ip, self.server.ip, 64)
            .tcp(self.client.port, self.server.port, seq, self.window)
            .psh()
            .ack(ack);
        let mut buf = Vec::with_capacity(b.size(payload.len()));
        b.write(&mut buf, payload).unwrap();
        buf
    }

    pub fn server_psh_ack_to_client(&self, seq: u32, ack: u32, payload: &[u8]) -> Vec<u8> {
        let b = etherparse::PacketBuilder::ethernet2([0; 6], [0; 6])
            .ipv4(self.server.ip, self.client.ip, 64)
            .tcp(self.server.port, self.client.port, seq, self.window)
            .psh()
            .ack(ack);
        let mut buf = Vec::with_capacity(b.size(payload.len()));
        b.write(&mut buf, payload).unwrap();
        buf
    }
}

#[must_use]
pub struct TcpSessionScenario {
    session: TcpSessionV4,
    client_iface: Arc<str>,
    server_iface: Arc<str>,
    plan: ScenarioPlan,
    dangling_packet_expect: bool,
    client_seq_next: u32,
    server_seq_next: u32,
}

impl TcpSessionScenario {
    pub fn new(session: TcpSessionV4) -> Self {
        Self {
            session,
            client_iface: Arc::from("eth1"),
            server_iface: Arc::from("eth2"),
            plan: ScenarioPlan {
                sends: Vec::new(),
                event_expectations: Vec::new(),
            },
            dangling_packet_expect: false,
            client_seq_next: 0,
            server_seq_next: 0,
        }
    }

    pub fn on_client_iface(mut self, iface: impl Into<Arc<str>>) -> Self {
        self.client_iface = iface.into();
        self
    }

    pub fn on_server_iface(mut self, iface: impl Into<Arc<str>>) -> Self {
        self.server_iface = iface.into();
        self
    }

    pub fn open(mut self) -> Self {
        self.push_send(self.session.syn_from_client(), self.client_iface.clone());
        self.push_send(self.session.syn_ack_from_server(), self.server_iface.clone());
        self.push_send(self.session.ack_from_client(), self.client_iface.clone());
        self.client_seq_next = self.session.client_isn.wrapping_add(1);
        self.server_seq_next = self.session.server_isn.wrapping_add(1);
        self
    }

    pub fn client_sends(mut self, payload: &[u8]) -> Self {
        let raw = self
            .session
            .client_psh_ack_to_server(self.client_seq_next, self.server_seq_next, payload);
        self.client_seq_next = self
            .client_seq_next
            .wrapping_add(payload.len() as u32);
        self.push_send(raw, self.client_iface.clone());
        self
    }

    pub fn server_sends(mut self, payload: &[u8]) -> Self {
        let raw = self
            .session
            .server_psh_ack_to_client(self.server_seq_next, self.client_seq_next, payload);
        self.server_seq_next = self
            .server_seq_next
            .wrapping_add(payload.len() as u32);
        self.push_send(raw, self.server_iface.clone());
        self
    }

    fn push_send(&mut self, raw: Vec<u8>, iface: Arc<str>) {
        self.dangling_packet_expect = false;
        self.plan.sends.push(SendStep {
            raw,
            iface,
            expect_packet: None,
        });
    }

    pub fn expect_packet(mut self, expected: PipelineOutcome) -> Self {
        if let Some(last) = self.plan.sends.last_mut() {
            last.expect_packet = Some(expected);
            self.dangling_packet_expect = false;
        } else {
            self.dangling_packet_expect = true;
        }
        self
    }

    pub fn expect_event(mut self, pred: EventPredicate) -> Self {
        self.plan.event_expectations.push(pred);
        self
    }

    /// Clears `capture`, sets a new fence, runs sends, then checks packet expectations and (if any) event subsequence on `capture`.
    /// When running multiple tests in parallel, acquire [`crate::event_capture_concurrency_mutex`] before [`set_event_capture`] for the same `capture` instance this run uses.
    pub async fn run(
        self,
        daemon: &TestDaemon,
        capture: &Arc<EventCapture>,
    ) -> Result<(), ScenarioRunError> {
        if self.dangling_packet_expect {
            return Err(ScenarioRunError::ExpectPacketWithoutSend);
        }
        Box::pin(execute_scenario_plan(self.plan, daemon, capture)).await
    }
}

pub struct UdpSessionV4 {
    pub client: SocketV4,
    pub server: SocketV4,
}

impl UdpSessionV4 {
    pub fn new(client: SocketV4, server: SocketV4) -> Self {
        Self { client, server }
    }

    pub fn datagram_client_to_server(&self, payload: &[u8]) -> Vec<u8> {
        let b = etherparse::PacketBuilder::ethernet2([0; 6], [0; 6])
            .ipv4(self.client.ip, self.server.ip, 64)
            .udp(self.client.port, self.server.port);
        let mut buf = Vec::with_capacity(b.size(payload.len()));
        b.write(&mut buf, payload).unwrap();
        buf
    }

    pub fn datagram_server_to_client(&self, payload: &[u8]) -> Vec<u8> {
        let b = etherparse::PacketBuilder::ethernet2([0; 6], [0; 6])
            .ipv4(self.server.ip, self.client.ip, 64)
            .udp(self.server.port, self.client.port);
        let mut buf = Vec::with_capacity(b.size(payload.len()));
        b.write(&mut buf, payload).unwrap();
        buf
    }
}

pub struct IcmpSessionV4 {
    pub client_ip: [u8; 4],
    pub server_ip: [u8; 4],
}

impl IcmpSessionV4 {
    pub fn new(client_ip: [u8; 4], server_ip: [u8; 4]) -> Self {
        Self {
            client_ip,
            server_ip,
        }
    }

    pub fn echo_request(&self, id: u16, seq: u16, payload: &[u8]) -> Vec<u8> {
        let b = etherparse::PacketBuilder::ethernet2([0; 6], [0; 6])
            .ipv4(self.client_ip, self.server_ip, 64)
            .icmpv4_echo_request(id, seq);
        let mut buf = Vec::with_capacity(b.size(payload.len()));
        b.write(&mut buf, payload).unwrap();
        buf
    }

    pub fn echo_reply(&self, id: u16, seq: u16, payload: &[u8]) -> Vec<u8> {
        let b = etherparse::PacketBuilder::ethernet2([0; 6], [0; 6])
            .ipv4(self.server_ip, self.client_ip, 64)
            .icmpv4_echo_reply(id, seq);
        let mut buf = Vec::with_capacity(b.size(payload.len()));
        b.write(&mut buf, payload).unwrap();
        buf
    }
}

pub fn icmp_echo_ipv4(src: [u8; 4], dst: [u8; 4]) -> Vec<u8> {
    IcmpSessionV4::new(src, dst).echo_request(1, 1, &[])
}

pub struct Scenario;

impl Scenario {
    pub fn packets() -> PacketsScenario {
        packets()
    }

    pub fn tcp(client: SocketV4, server: SocketV4) -> TcpSessionScenario {
        TcpSessionScenario::new(TcpSessionV4::new(client, server))
    }

    pub fn udp_session(client: SocketV4, server: SocketV4) -> UdpSessionV4 {
        UdpSessionV4::new(client, server)
    }

    pub fn icmp_session(client_ip: [u8; 4], server_ip: [u8; 4]) -> IcmpSessionV4 {
        IcmpSessionV4::new(client_ip, server_ip)
    }

    pub async fn run_expect_events<F, Fut>(
        capture: &EventCapture,
        stimulus: F,
        pattern_kinds: &[EventKind],
    ) -> Result<(), WaitForSubsequenceError>
    where
        F: FnOnce() -> Fut,
        Fut: Future<Output = ()>,
    {
        expect_events(capture, stimulus, pattern_kinds).await
    }
}

impl Default for PacketsScenario {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use etherparse::PacketHeaders;

    fn parse_tcp(raw: &[u8]) -> (etherparse::NetHeaders, etherparse::TcpHeader, Vec<u8>) {
        let pkt = PacketHeaders::from_ethernet_slice(raw).expect("parse packet");
        let ip = pkt.net.expect("ip header");
        let tcp = pkt.transport.expect("transport header").tcp().expect("tcp header");
        (ip, tcp, pkt.payload.slice().to_vec())
    }

    #[test]
    fn tcp_builder_syn_from_client_fields() {
        let client = SocketV4 {
            ip: [192, 168, 10, 10],
            port: 40_000,
        };
        let server = SocketV4 {
            ip: [192, 168, 20, 20],
            port: 25,
        };
        let session = TcpSessionV4::new(client, server).with_isns(1234, 4321).with_window(4096);

        let raw = session.syn_from_client();
        let (ip, tcp, payload) = parse_tcp(&raw);
        let etherparse::NetHeaders::Ipv4(header, _) = ip else {
            panic!("expected ipv4 header");
        };

        assert_eq!(header.source, client.ip);
        assert_eq!(header.destination, server.ip);
        assert!(tcp.syn);
        assert!(!tcp.ack);
        assert_eq!(tcp.sequence_number, 1234);
        assert_eq!(tcp.destination_port, server.port);
        assert_eq!(tcp.source_port, client.port);
        assert!(payload.is_empty());
    }

    #[test]
    fn tcp_builder_syn_ack_from_server_fields() {
        let client = SocketV4 {
            ip: [192, 168, 10, 10],
            port: 40_000,
        };
        let server = SocketV4 {
            ip: [192, 168, 20, 20],
            port: 25,
        };
        let session = TcpSessionV4::new(client, server).with_isns(1000, 2000);

        let raw = session.syn_ack_from_server();
        let (ip, tcp, payload) = parse_tcp(&raw);
        let etherparse::NetHeaders::Ipv4(header, _) = ip else {
            panic!("expected ipv4 header");
        };

        assert_eq!(header.source, server.ip);
        assert_eq!(header.destination, client.ip);
        assert!(tcp.syn);
        assert!(tcp.ack);
        assert_eq!(tcp.sequence_number, 2000);
        assert_eq!(tcp.acknowledgment_number, 1001);
        assert_eq!(tcp.destination_port, client.port);
        assert_eq!(tcp.source_port, server.port);
        assert!(payload.is_empty());
    }

    #[test]
    fn tcp_builder_ack_from_client_fields() {
        let client = SocketV4 {
            ip: [192, 168, 10, 10],
            port: 40_000,
        };
        let server = SocketV4 {
            ip: [192, 168, 20, 20],
            port: 25,
        };
        let session = TcpSessionV4::new(client, server).with_isns(1000, 2000);

        let raw = session.ack_from_client();
        let (ip, tcp, payload) = parse_tcp(&raw);
        let etherparse::NetHeaders::Ipv4(header, _) = ip else {
            panic!("expected ipv4 header");
        };

        assert_eq!(header.source, client.ip);
        assert_eq!(header.destination, server.ip);
        assert!(!tcp.syn);
        assert!(tcp.ack);
        assert_eq!(tcp.sequence_number, 1001);
        assert_eq!(tcp.acknowledgment_number, 2001);
        assert_eq!(tcp.destination_port, server.port);
        assert_eq!(tcp.source_port, client.port);
        assert!(payload.is_empty());
    }

    #[test]
    fn tcp_builder_client_psh_ack_payload() {
        let client = SocketV4 {
            ip: [192, 168, 10, 10],
            port: 40_000,
        };
        let server = SocketV4 {
            ip: [192, 168, 20, 20],
            port: 25,
        };
        let session = TcpSessionV4::new(client, server).with_window(2048);
        let payload = b"ping";

        let raw = session.client_psh_ack_to_server(77, 88, payload);
        let (_ip, tcp, parsed_payload) = parse_tcp(&raw);

        assert!(tcp.psh);
        assert!(tcp.ack);
        assert_eq!(tcp.sequence_number, 77);
        assert_eq!(tcp.acknowledgment_number, 88);
        assert_eq!(parsed_payload, payload);
    }

    #[test]
    fn tcp_builder_server_psh_ack_payload() {
        let client = SocketV4 {
            ip: [192, 168, 10, 10],
            port: 40_000,
        };
        let server = SocketV4 {
            ip: [192, 168, 20, 20],
            port: 25,
        };
        let session = TcpSessionV4::new(client, server).with_window(2048);
        let payload = b"pong";

        let raw = session.server_psh_ack_to_client(99, 111, payload);
        let (_ip, tcp, parsed_payload) = parse_tcp(&raw);

        assert!(tcp.psh);
        assert!(tcp.ack);
        assert_eq!(tcp.sequence_number, 99);
        assert_eq!(tcp.acknowledgment_number, 111);
        assert_eq!(parsed_payload, payload);
    }

    #[test]
    fn udp_builder_fields() {
        let client = SocketV4 {
            ip: [192, 168, 10, 10],
            port: 40_000,
        };
        let server = SocketV4 {
            ip: [192, 168, 20, 20],
            port: 53,
        };
        let session = UdpSessionV4::new(client, server);
        let payload = b"dns";

        let raw = session.datagram_client_to_server(payload);
        let pkt = PacketHeaders::from_ethernet_slice(&raw).expect("parse packet");
        let etherparse::NetHeaders::Ipv4(header, _) = pkt.net.expect("ip header") else {
            panic!("expected ipv4 header");
        };
        let udp = pkt.transport.expect("transport header").udp().expect("udp header");

        assert_eq!(header.source, client.ip);
        assert_eq!(header.destination, server.ip);
        assert_eq!(udp.source_port, client.port);
        assert_eq!(udp.destination_port, server.port);
        assert_eq!(pkt.payload.slice(), payload);
    }

    #[test]
    fn icmp_builder_fields() {
        let session = IcmpSessionV4::new([192, 168, 10, 10], [192, 168, 20, 20]);
        let payload = b"ping";

        let raw = session.echo_request(7, 9, payload);
        let pkt = PacketHeaders::from_ethernet_slice(&raw).expect("parse packet");
        let icmp = pkt.transport.expect("transport header").icmpv4().expect("icmp header");

        assert!(matches!(icmp.icmp_type, etherparse::Icmpv4Type::EchoRequest(h) if h.id == 7 && h.seq == 9));
        assert_eq!(pkt.payload.slice(), payload);

        let raw = session.echo_reply(3, 4, payload);
        let pkt = PacketHeaders::from_ethernet_slice(&raw).expect("parse packet");
        let icmp = pkt.transport.expect("transport header").icmpv4().expect("icmp header");

        assert!(matches!(icmp.icmp_type, etherparse::Icmpv4Type::EchoReply(h) if h.id == 3 && h.seq == 4));
        assert_eq!(pkt.payload.slice(), payload);
    }

    #[test]
    fn icmp_echo_ipv4_defaults() {
        let raw = icmp_echo_ipv4([192, 168, 10, 10], [192, 168, 20, 20]);
        let pkt = PacketHeaders::from_ethernet_slice(&raw).expect("parse packet");
        let icmp = pkt.transport.expect("transport header").icmpv4().expect("icmp header");

        assert!(matches!(icmp.icmp_type, etherparse::Icmpv4Type::EchoRequest(h) if h.id == 1 && h.seq == 1));
        assert!(pkt.payload.slice().is_empty());
    }
}
