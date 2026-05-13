use std::future::Future;
use std::sync::Arc;

use ngfw::daemon::Daemon;

use crate::{expect_events, EventCapture, EventKind, WaitForSubsequenceError};

pub struct RawPacketStep {
    pub raw: Vec<u8>,
    pub iface: Arc<str>,
}

pub struct PacketsScenario {
    steps: Vec<RawPacketStep>,
    default_iface: Arc<str>,
}

impl PacketsScenario {
    pub fn new() -> Self {
        Self {
            steps: Vec::new(),
            default_iface: Arc::from("eth1"),
        }
    }

    pub fn on_iface(mut self, iface: impl Into<Arc<str>>) -> Self {
        self.default_iface = iface.into();
        self
    }

    pub fn send(mut self, raw: Vec<u8>) -> Self {
        self.steps.push(RawPacketStep {
            raw,
            iface: self.default_iface.clone(),
        });
        self
    }

    pub async fn run<D: ngfw::daemon::DaemonDeps>(self, daemon: &Daemon<D>) {
        for step in self.steps {
            let _ = daemon.process_raw(step.raw, step.iface).await;
        }
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

    pub fn tcp_session(client: SocketV4, server: SocketV4) -> TcpSessionV4 {
        TcpSessionV4::new(client, server)
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
