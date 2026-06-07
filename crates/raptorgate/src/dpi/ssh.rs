use std::{collections::VecDeque, sync::Arc};

use derive_more::derive;
use ssh_parser::{SshPacket, SshVersion, parse_ssh_identification, parse_ssh_packet};

use crate::{conntrack::tuple::Direction, data_plane::packet_context::PacketId, dpi::smtp::{smtp_policy_retriever::SmtpPolicyRetriever, BufferingDisposition, PacketAction, UnitStatus}, l4::{L4Outcome, SessionContext}, zones::resolver::ZoneResolver};

const MAX_HANDSHAKE_PACKET_SIZE: usize = 2048;

#[derive(Debug, Clone, PartialEq, Eq)]
enum SshHost {
    Client,
    Server,
}

impl From<Direction> for SshHost {
    fn from(dir: Direction) -> Self {
        match dir {
            Direction::Original => SshHost::Client,
            Direction::Reply => SshHost::Server,
        }
    }
}

#[derive(Debug, Clone)]
enum SshState {
    Clear(ClearStage),
    Encrypted
}

#[derive(Debug, Clone)]
enum ClearState {
    VersionExchange,
    AlgorithmNegotiation,
    KeyExchange,
    NewKeys,
}

#[derive(Debug, Clone)]
struct ClearStage {
    state: ClearState,
    expected_host: SshHost,
}

impl SshState {
    fn next_state_or_host(&mut self) -> Result<(), ()> {
        if let SshState::Clear(c) = self.clone() {
            if c.expected_host == SshHost::Client {
                *self = SshState::Clear(ClearStage { state: c.state, expected_host: SshHost::Server });
                return Ok(())
            }

            match c.state {
                ClearState::VersionExchange => *self = SshState::Clear(ClearStage { state: ClearState::AlgorithmNegotiation, expected_host: SshHost::Client }),
                ClearState::AlgorithmNegotiation => *self = SshState::Clear(ClearStage { state: ClearState::KeyExchange, expected_host: SshHost::Client }),
                ClearState::KeyExchange => *self = SshState::Clear(ClearStage { state: ClearState::NewKeys, expected_host: SshHost::Client }),
                ClearState::NewKeys => *self = SshState::Encrypted,
            }

            return Ok(())
        }

        Err(())
    }


    pub fn advance_with_version(&mut self, from: SshHost) -> Result<(), ()> {
        match self {
            SshState::Clear(ClearStage { state: ClearState::VersionExchange, expected_host: s }) if *s == from => {
                self.next_state_or_host()
            }

            _ => Err(())
        }
    }

    pub fn advance_with_packet(&mut self, new_packet: &SshPacket, from: SshHost) -> Result<(), ()> {
        let is_valid = match self {
            SshState::Clear(ClearStage { state, expected_host }) if *expected_host == from => {
                match (state, from) {
                    (ClearState::AlgorithmNegotiation, _) => {
                        matches!(new_packet, SshPacket::KeyExchange(_))
                    }
                    (ClearState::KeyExchange, SshHost::Client) => {
                        matches!(new_packet, SshPacket::DiffieHellmanInit(_))
                    }
                    (ClearState::KeyExchange, SshHost::Server) => {
                        matches!(new_packet, SshPacket::DiffieHellmanReply(_))
                    }
                    (ClearState::NewKeys, _) => {
                        matches!(new_packet, SshPacket::NewKeys)
                    }
                    _ => false,
                }
            }
            _ => false,
        };

        if is_valid {
            self.next_state_or_host()
        } else {
            Err(())
        }
    }
}

#[derive(Debug)]
enum AssemblerVerdict {
    NeedMore,
    PacketComplete(Vec<u8>),
    TooLarge,
    Invalid,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SshVersionOwned {
    pub proto: Vec<u8>,
    pub software: Vec<u8>,
    pub comments: Option<Vec<u8>>,
}

impl<'a> From<SshVersion<'a>> for SshVersionOwned {
    fn from(v: SshVersion<'a>) -> Self {
        Self {
            proto: v.proto.to_vec(),
            software: v.software.to_vec(),
            comments: v.comments.map(Vec::from),
        }
    }
}


struct SshSessionInfo {
    version_client_banner: Option<SshVersionOwned>,
    version_server_banner: Option<SshVersionOwned>,
}

struct SshSession<ZR> where ZR: ZoneResolver {
    state: SshState,
    assembler: SshPacketAssembler,
    confirmed_ssh: bool,

    buffered_ids: VecDeque<PacketId>,
    policy_retriever: Arc<SmtpPolicyRetriever<ZR>>,
}


impl<ZR> SshSession<ZR> where ZR: ZoneResolver {
    pub fn new(policy_retriever: Arc<SmtpPolicyRetriever<ZR>>) -> Self {
        SshSession { state: SshState::Clear(ClearStage { state: ClearState::VersionExchange, expected_host: SshHost::Client }), buffered_ids: VecDeque::new(), policy_retriever, assembler: SshPacketAssembler::new(), confirmed_ssh: false }
    }

    pub(crate) fn process_bytes(
        &mut self,
        ctx: &mut SessionContext,
        packet_id: PacketId,
        dir: Direction,
        payload: &[u8],
    ) -> BufferingDisposition {
        if matches!(self.state, SshState::Encrypted) {
            return BufferingDisposition { packet: PacketAction::Pass, unit: UnitStatus::Complete }
        }

        let body = match self.assembler.push(payload, self.state.clone()) {
            AssemblerVerdict::NeedMore => return BufferingDisposition { packet: PacketAction::QueueAndHalt, unit: UnitStatus::Incomplete },
            AssemblerVerdict::TooLarge | AssemblerVerdict::Invalid => {
                if !self.confirmed_ssh {
                    return BufferingDisposition { packet: PacketAction::Pass, unit: UnitStatus::Complete }
                }

                return BufferingDisposition { packet: PacketAction::Drop, unit: UnitStatus::Complete }
            }
            AssemblerVerdict::PacketComplete(p) => p,

        };

        if matches!(self.state, SshState::Clear(ClearStage { state: ClearState::VersionExchange, .. })) {
            let Ok((_, (_banners, _version))) = parse_ssh_identification(&body) else {
                if !self.confirmed_ssh {
                    return BufferingDisposition { packet: PacketAction::Pass, unit: UnitStatus::Complete }
                }

                return BufferingDisposition { packet: PacketAction::Drop, unit: UnitStatus::Complete }
            };

            if self.state.advance_with_version(SshHost::from(dir)).is_err() {
                return BufferingDisposition { packet: PacketAction::Drop, unit: UnitStatus::Complete }
            }

            return BufferingDisposition { packet: PacketAction::Pass, unit: UnitStatus::Complete }
        }

        let mut wire = Vec::with_capacity(4 + body.len());
        wire.extend_from_slice(&(body.len() as u32).to_be_bytes());
        wire.extend_from_slice(&body);
        let parsed = parse_ssh_packet(&wire);

        match parsed {
            Ok((_, (ssh_packet, _))) => {
                let from = SshHost::from(dir);
                match &ssh_packet {
                    SshPacket::KeyExchange(_)
                    | SshPacket::NewKeys
                    | SshPacket::DiffieHellmanInit(_)
                    | SshPacket::DiffieHellmanReply(_) => {
                        if self.state.advance_with_packet(&ssh_packet, from).is_err() {
                            return BufferingDisposition { packet: PacketAction::Drop, unit: UnitStatus::Complete }
                        }
                    }
                    _ => {}
                }
            }
            Err(_) => return BufferingDisposition { packet: PacketAction::Drop, unit: UnitStatus::Complete },
        }

        BufferingDisposition { packet: PacketAction::Pass, unit: UnitStatus::Complete }
    }
}

struct SshPacketAssembler {
    buffer: Vec<u8>,
}

impl SshPacketAssembler {
    pub fn new() -> Self {
        Self { buffer: Vec::new() }
    }
    pub fn push(&mut self, payload: &[u8], current_stage: SshState) -> AssemblerVerdict {
        if self.buffer.len() + payload.len() > MAX_HANDSHAKE_PACKET_SIZE {
            self.buffer.clear();
            return AssemblerVerdict::TooLarge;
        }

        self.buffer.extend_from_slice(payload);

        if matches!(current_stage, SshState::Clear(ClearStage { state: ClearState::VersionExchange, .. })) {
            if let Some(pos) = self.buffer.iter().position(|&b| b == b'\n') {
                let line: Vec<u8> = self.buffer.drain(..pos + 1).collect();
                return AssemblerVerdict::PacketComplete(line);
            }
            return AssemblerVerdict::NeedMore;
        }

        if self.buffer.len() < 4 {
            return AssemblerVerdict::NeedMore;
        }

        let declared_length = u32::from_be_bytes(self.buffer[..4].try_into().unwrap_or([0, 0, 0, 0]));

        if declared_length > MAX_HANDSHAKE_PACKET_SIZE as u32 || declared_length == 0 {
            return AssemblerVerdict::Invalid;
        }

        if self.buffer.len() >= 4 + declared_length as usize {
            AssemblerVerdict::PacketComplete(
                self.buffer
                    .drain(..4 + declared_length as usize)
                    .skip(4)
                    .collect()
            )
        } else {
            AssemblerVerdict::NeedMore
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use std::collections::HashMap;
    use std::net::{IpAddr, Ipv4Addr};
    use std::path::PathBuf;
    use std::sync::Arc;
    use std::time::Duration;

    use ssh_parser::serialize::gen_ssh_packet;
    use ssh_parser::{SshPacket, SshPacketDhInit, SshPacketDhReply, SshPacketKeyExchange};
    use uuid::Uuid;

    use crate::conntrack::proto::tcp::{TcpConntrack, TcpProtoState};
    use crate::conntrack::proto::ProtoState;
    use crate::conntrack::tuple::{FlowTuple, Protocol};
    use crate::l4::SessionContext;
    use crate::policy::provider::DiskPolicyProvider;
    use crate::policy::{Policy, PolicyId};
    use crate::zones::resolver::ZoneResolver;
    use crate::zones::{DefaultPolicy, DirectionalZonePairs, ResolvedZonePair, ZonePairId};

    fn in_clear(state: ClearState, host: SshHost) -> SshState {
        SshState::Clear(ClearStage { state, expected_host: host })
    }

    struct StubZoneResolver;

    impl ZoneResolver for StubZoneResolver {
        fn resolve(&self, _src_interface_name: &str, _dst_ip: IpAddr) -> Option<ResolvedZonePair> {
            None
        }

        fn resolve_bidirectional(&self, _src_ip: IpAddr, _dst_ip: IpAddr) -> DirectionalZonePairs {
            let pair = ResolvedZonePair {
                id: ZonePairId::from(Uuid::nil()),
                default_policy: DefaultPolicy::Allow,
            };
            DirectionalZonePairs {
                forward: Some(pair.clone()),
                reverse: Some(pair),
            }
        }
    }

    fn mock_policy_retriever() -> Arc<SmtpPolicyRetriever<StubZoneResolver>> {
        let zone_resolver = Arc::new(StubZoneResolver);
        let policy_provider = Arc::new(DiskPolicyProvider::from_policies(
            HashMap::<PolicyId, Policy>::new(),
            PathBuf::from("/tmp"),
        ));
        Arc::new(SmtpPolicyRetriever::new(zone_resolver, policy_provider))
    }

    fn session_context() -> SessionContext {
        let mut tcp = TcpProtoState::default();
        tcp.state = TcpConntrack::Established;

        let tuple = FlowTuple::new(
            IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)),
            54321,
            IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2)),
            22,
            Protocol::Tcp,
        );

        let entry = Arc::new(crate::conntrack::entry::ConntrackEntry::new(
            1,
            tuple,
            ProtoState::Tcp(tcp),
            Duration::from_secs(60),
            0,
        ));
        SessionContext::open(entry, &StubZoneResolver)
    }

    fn serialize(packet: &SshPacket) -> Vec<u8> {
        let mut buf = vec![0u8; 4096];
        let (_, written) = gen_ssh_packet((&mut buf, 0), packet).expect("gen_ssh_packet");
        buf.truncate(written);
        buf
    }

    fn kex_init_bytes() -> Vec<u8> {
        serialize(&SshPacket::KeyExchange(SshPacketKeyExchange {
            cookie: &[0u8; 16],
            kex_algs: &[],
            server_host_key_algs: &[],
            encr_algs_client_to_server: &[],
            encr_algs_server_to_client: &[],
            mac_algs_client_to_server: &[],
            mac_algs_server_to_client: &[],
            comp_algs_client_to_server: &[],
            comp_algs_server_to_client: &[],
            langs_client_to_server: &[],
            langs_server_to_client: &[],
            first_kex_packet_follows: false,
        }))
    }

    fn dh_init_bytes() -> Vec<u8> {
        serialize(&SshPacket::DiffieHellmanInit(SshPacketDhInit { e: &[] }))
    }

    fn dh_reply_bytes() -> Vec<u8> {
        serialize(&SshPacket::DiffieHellmanReply(SshPacketDhReply {
            pubkey_and_cert: &[],
            f: &[],
            signature: &[],
        }))
    }

    fn new_keys_bytes() -> Vec<u8> {
        serialize(&SshPacket::NewKeys)
    }

    fn drive(
        session: &mut SshSession<StubZoneResolver>,
        ctx: &mut SessionContext,
        dir: Direction,
        payload: &[u8],
    ) -> BufferingDisposition {
        session.process_bytes(ctx, PacketId::default(), dir, payload)
    }

    fn run_two_cycles(
        assembler: &mut SshPacketAssembler,
        cycle1: &[u8],
        cycle2: &[u8],
        state: SshState,
    ) -> [AssemblerVerdict; 7] {
        debug_assert!(cycle1.len() >= 4 && cycle2.len() >= 4);
        let split1 = cycle1.len() / 4;
        let split2 = cycle2.len() / 4;

        let mut v = Vec::with_capacity(7);
        v.push(assembler.push(&cycle1[..split1], state.clone()));
        v.push(assembler.push(&cycle1[split1..2 * split1], state.clone()));
        v.push(assembler.push(&cycle1[2 * split1..3 * split1], state.clone()));
        let mut push4 = Vec::from(&cycle1[3 * split1..]);
        push4.extend_from_slice(&cycle2[..split2]);
        v.push(assembler.push(&push4, state.clone()));
        v.push(assembler.push(&cycle2[split2..2 * split2], state.clone()));
        v.push(assembler.push(&cycle2[2 * split2..3 * split2], state.clone()));
        v.push(assembler.push(&cycle2[3 * split2..], state.clone()));

        v.try_into().unwrap()
    }

    #[test]
    fn version_exchange_packet_complete() {
        let mut a = SshPacketAssembler::new();
        let cycle1: &[u8] = b"SSH-2.0-OpenSSH_8.9\r\n";
        let cycle2: &[u8] = b"SSH-2.0-dropbear_2022.83\r\n";
        let v = run_two_cycles(
            &mut a,
            cycle1,
            cycle2,
            in_clear(ClearState::VersionExchange, SshHost::Client),
        );
        match &v[3] {
            AssemblerVerdict::PacketComplete(bytes) => assert_eq!(bytes, cycle1),
            _ => panic!("expected PacketComplete at push 4"),
        }
        match &v[6] {
            AssemblerVerdict::PacketComplete(bytes) => assert_eq!(bytes, cycle2),
            _ => panic!("expected PacketComplete at push 7"),
        }
    }

    #[test]
    fn version_exchange_need_more() {
        let mut a = SshPacketAssembler::new();
        let cycle1: &[u8] = b"xxxxxxxxxxxxxxxxxxxx";
        let cycle2: &[u8] = b"yyyyyyyyyyyyyyyy";
        let v = run_two_cycles(
            &mut a,
            cycle1,
            cycle2,
            in_clear(ClearState::VersionExchange, SshHost::Client),
        );
        for (i, verdict) in v.iter().enumerate() {
            assert!(
                matches!(verdict, AssemblerVerdict::NeedMore),
                "verdict {i} expected NeedMore"
            );
        }
    }

    #[test]
    fn version_exchange_too_large() {
        let mut a = SshPacketAssembler::new();
        let cycle1 = vec![b'X'; 2052];
        let cycle2 = vec![b'X'; 2052];
        let v = run_two_cycles(
            &mut a,
            &cycle1,
            &cycle2,
            in_clear(ClearState::VersionExchange, SshHost::Client),
        );
        assert!(
            matches!(v[3], AssemblerVerdict::TooLarge),
            "expected TooLarge at push 4, got {:?}",
            v[3]
        );
    }

    #[test]
    fn regular_packet_complete() {
        let mut a = SshPacketAssembler::new();
        let mut cycle1 = vec![0u8, 0, 0, 12];
        cycle1.extend_from_slice(b"abcdefghijkl");
        let mut cycle2 = vec![0u8, 0, 0, 12];
        cycle2.extend_from_slice(b"mnopqrstuvwx");
        let v = run_two_cycles(
            &mut a,
            &cycle1,
            &cycle2,
            in_clear(ClearState::AlgorithmNegotiation, SshHost::Client),
        );
        match &v[3] {
            AssemblerVerdict::PacketComplete(bytes) => assert_eq!(bytes, b"abcdefghijkl"),
            _ => panic!("expected PacketComplete at push 4"),
        }
        match &v[6] {
            AssemblerVerdict::PacketComplete(bytes) => assert_eq!(bytes, b"mnopqrstuvwx"),
            _ => panic!("expected PacketComplete at push 7"),
        }
    }

    #[test]
    fn regular_need_more() {
        let mut a = SshPacketAssembler::new();
        let v = run_two_cycles(
            &mut a,
            &[0, 0, 0, 100, b'X'],
            &[0, 0, 0, 100, b'Y'],
            in_clear(ClearState::AlgorithmNegotiation, SshHost::Client),
        );
        for (i, verdict) in v.iter().enumerate() {
            assert!(
                matches!(verdict, AssemblerVerdict::NeedMore),
                "verdict {i} expected NeedMore"
            );
        }
    }

    #[test]
    fn regular_invalid() {
        let mut a = SshPacketAssembler::new();
        let v = run_two_cycles(
            &mut a,
            &[0, 0, 0, 0, b'X'],
            &[0, 0, 0, 0, b'Y'],
            in_clear(ClearState::AlgorithmNegotiation, SshHost::Client),
        );
        assert!(
            matches!(v[3], AssemblerVerdict::Invalid),
            "expected Invalid at push 4, got {:?}",
            v[3]
        );
    }

    #[test]
    fn regular_too_large() {
        let mut a = SshPacketAssembler::new();
        let cycle1 = vec![b'X'; 2052];
        let cycle2 = vec![b'X'; 2052];
        let v = run_two_cycles(
            &mut a,
            &cycle1,
            &cycle2,
            in_clear(ClearState::AlgorithmNegotiation, SshHost::Client),
        );
        assert!(
            matches!(v[3], AssemblerVerdict::TooLarge),
            "expected TooLarge at push 4, got {:?}",
            v[3]
        );
    }

    #[test]
    fn fragmented_packet_size() {
        let mut a = SshPacketAssembler::new();
        let packet: &[u8] = &[0, 0, 0, 8, b'a', b'b', b'c', b'd', b'e', b'f', b'g', b'h'];
        let state = in_clear(ClearState::AlgorithmNegotiation, SshHost::Client);
        let mut verdicts = Vec::new();
        for byte in packet {
            verdicts.push(a.push(&[*byte], state.clone()));
        }
        assert_eq!(verdicts.len(), 12);
        for (i, verdict) in verdicts.iter().enumerate().take(7) {
            assert!(
                matches!(verdict, AssemblerVerdict::NeedMore),
                "verdict {i} expected NeedMore"
            );
        }
        match &verdicts[11] {
            AssemblerVerdict::PacketComplete(bytes) => assert_eq!(bytes, b"abcdefgh"),
            _ => panic!("expected PacketComplete at push 12, got {:?}", verdicts[11]),
        }
    }

    #[test]
    fn full_ssh_handshake_transitions_to_encrypted() {
        let mut session = SshSession::new(mock_policy_retriever());
        let mut ctx = session_context();

        assert!(matches!(
            session.state,
            SshState::Clear(ClearStage {
                state: ClearState::VersionExchange,
                expected_host: SshHost::Client
            })
        ));

        let d = drive(
            &mut session,
            &mut ctx,
            Direction::Original,
            b"SSH-2.0-OpenSSH_8.9\r\n",
        );
        assert_eq!(
            d,
            BufferingDisposition { packet: PacketAction::Pass, unit: UnitStatus::Complete }
        );
        assert!(matches!(
            session.state,
            SshState::Clear(ClearStage {
                state: ClearState::VersionExchange,
                expected_host: SshHost::Server
            })
        ));

        drive(
            &mut session,
            &mut ctx,
            Direction::Reply,
            b"SSH-2.0-dropbear_2022.83\r\n",
        );
        assert!(matches!(
            session.state,
            SshState::Clear(ClearStage {
                state: ClearState::AlgorithmNegotiation,
                expected_host: SshHost::Client
            })
        ));

        drive(&mut session, &mut ctx, Direction::Original, &kex_init_bytes());
        assert!(matches!(
            session.state,
            SshState::Clear(ClearStage {
                state: ClearState::AlgorithmNegotiation,
                expected_host: SshHost::Server
            })
        ));

        drive(&mut session, &mut ctx, Direction::Reply, &kex_init_bytes());
        assert!(matches!(
            session.state,
            SshState::Clear(ClearStage {
                state: ClearState::KeyExchange,
                expected_host: SshHost::Client
            })
        ));

        drive(&mut session, &mut ctx, Direction::Original, &dh_init_bytes());
        assert!(matches!(
            session.state,
            SshState::Clear(ClearStage {
                state: ClearState::KeyExchange,
                expected_host: SshHost::Server
            })
        ));

        drive(&mut session, &mut ctx, Direction::Reply, &dh_reply_bytes());
        assert!(matches!(
            session.state,
            SshState::Clear(ClearStage {
                state: ClearState::NewKeys,
                expected_host: SshHost::Client
            })
        ));

        drive(&mut session, &mut ctx, Direction::Original, &new_keys_bytes());
        assert!(matches!(
            session.state,
            SshState::Clear(ClearStage {
                state: ClearState::NewKeys,
                expected_host: SshHost::Server
            })
        ));

        drive(&mut session, &mut ctx, Direction::Reply, &new_keys_bytes());
        assert!(matches!(session.state, SshState::Encrypted));

        let d = drive(&mut session, &mut ctx, Direction::Original, b"\x00\x01\x02\x03");
        assert_eq!(
            d,
            BufferingDisposition { packet: PacketAction::Pass, unit: UnitStatus::Complete }
        );
    }
}
