use std::sync::Arc;

use ssh_parser::{SshPacket, SshVersion, parse_ssh_identification, parse_ssh_packet};

use crate::{conntrack::tuple::Direction, data_plane::packet_context::PacketId, dpi::smtp::{BufferingDisposition, PacketAction, UnitStatus, smtp_policy_retriever::SmtpPolicyRetriever}, l4::{AppProto, L4Outcome, SessionContext}, zones::resolver::ZoneResolver};

const MAX_HANDSHAKE_PACKET_SIZE: usize = 2048;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
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
    PartiallyEncrypted(SshHost),
    Encrypted,
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
        match self {
            SshState::Clear(ClearStage { state: ClearState::NewKeys, .. }) => {
                if !matches!(new_packet, SshPacket::NewKeys) {
                    return Err(());
                }
                *self = SshState::PartiallyEncrypted(from);
                Ok(())
            }
            SshState::PartiallyEncrypted(encrypted) => {
                if from != *encrypted && matches!(new_packet, SshPacket::NewKeys) {
                    *self = SshState::Encrypted;
                    Ok(())
                } else {
                    Err(())
                }
            }
            SshState::Clear(ClearStage { state: ClearState::KeyExchange, expected_host })
                if *expected_host == from =>
            {
                let ok = match from {
                    SshHost::Client => matches!(new_packet, SshPacket::DiffieHellmanInit(_)),
                    SshHost::Server => matches!(new_packet, SshPacket::DiffieHellmanReply(_)),
                };
                if ok { self.next_state_or_host() } else { Err(()) }
            }
            SshState::Clear(ClearStage { state: ClearState::AlgorithmNegotiation, .. }) => {
                if matches!(new_packet, SshPacket::KeyExchange(_)) {
                    self.next_state_or_host()
                } else {
                    Err(())
                }
            }
            _ => Err(()),
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

pub(crate) struct SshSession<ZR> where ZR: ZoneResolver {
    state: SshState,
    assemblers: [SshPacketAssembler; 2],
    confirmed_ssh: bool,
    policy_retriever: Arc<SmtpPolicyRetriever<ZR>>,
}


impl<ZR> SshSession<ZR> where ZR: ZoneResolver {
    pub fn new(policy_retriever: Arc<SmtpPolicyRetriever<ZR>>) -> Self {
        SshSession {
            state: SshState::Clear(ClearStage {
                state: ClearState::VersionExchange,
                expected_host: SshHost::Client,
            }),
            assemblers: [SshPacketAssembler::new(), SshPacketAssembler::new()],
            confirmed_ssh: false,
            policy_retriever,
        }
    }

    fn get_assembler_for(&mut self, host: SshHost) -> &mut SshPacketAssembler {
        match host {
            SshHost::Client => &mut self.assemblers[0],
            SshHost::Server => &mut self.assemblers[1],
        }
    }

    fn handle_complete_message(
        &mut self,
        ctx: &mut SessionContext,
        body: Vec<u8>,
        host: SshHost,
    ) -> Result<(), ()> {
        if !self.confirmed_ssh {
            self.confirmed_ssh = true;
            ctx.set_application_protocol(AppProto::Ssh);
        }

        if matches!(self.state, SshState::Clear(ClearStage { state: ClearState::VersionExchange, .. })) {
            let Ok((_, _)) = parse_ssh_identification(&body) else { return Err(()) };
            self.state.advance_with_version(host).map_err(|_| ())
        } else {
            let mut wire = Vec::with_capacity(4 + body.len());
            wire.extend_from_slice(&(body.len() as u32).to_be_bytes());
            wire.extend_from_slice(&body);
            let Ok((_, (packet, _))) = parse_ssh_packet(&wire) else { return Err(()) };
            self.state.advance_with_packet(&packet, host).map_err(|_| ())
        }
    }

    pub(crate) fn process_bytes(
        &mut self,
        ctx: &mut SessionContext,
        packet_id: PacketId,
        dir: Direction,
        payload: &[u8],
    ) -> BufferingDisposition {
        let host = SshHost::from(dir);

        match &self.state {
            SshState::Encrypted => return BufferingDisposition { packet: PacketAction::Pass, unit: UnitStatus::Complete },
            SshState::PartiallyEncrypted(h) if *h == host => return BufferingDisposition { packet: PacketAction::Pass, unit: UnitStatus::Complete },
            _ => {},
        }

        self.get_assembler_for(host).push(payload);

        loop {
            let stage = self.state.clone();
            let verdict = self.get_assembler_for(host).take(&stage);
            match verdict {
                AssemblerVerdict::NeedMore => {
                    return BufferingDisposition { packet: PacketAction::QueueAndHalt, unit: UnitStatus::Incomplete };
                }
                AssemblerVerdict::TooLarge | AssemblerVerdict::Invalid => {
                    if !self.confirmed_ssh {
                        return BufferingDisposition { packet: PacketAction::Pass, unit: UnitStatus::Complete };
                    }
                    return BufferingDisposition { packet: PacketAction::Drop, unit: UnitStatus::Complete };
                }
                AssemblerVerdict::PacketComplete(body) => {
                    if self.handle_complete_message(ctx, body, host).is_err() {
                        return BufferingDisposition { packet: PacketAction::Drop, unit: UnitStatus::Complete };
                    }
                    let should_pass = match &self.state {
                        SshState::Encrypted => true,
                        SshState::PartiallyEncrypted(h) => *h == host,
                        _ => false,
                    };
                    if should_pass {
                        self.get_assembler_for(host).clear();
                        return BufferingDisposition { packet: PacketAction::Pass, unit: UnitStatus::Complete };
                    }
                    continue;
                }
            }
        }
    }
}

struct SshPacketAssembler {
    buffer: Vec<u8>,
    overflowed: bool,
}

impl SshPacketAssembler {
    pub fn new() -> Self {
        Self { buffer: Vec::new(), overflowed: false }
    }

    pub fn push(&mut self, payload: &[u8]) {
        if self.overflowed {
            return;
        }
        if self.buffer.len() + payload.len() > MAX_HANDSHAKE_PACKET_SIZE {
            self.buffer.clear();
            self.overflowed = true;
            return;
        }
        self.buffer.extend_from_slice(payload);
    }

    pub fn take(&mut self, stage: &SshState) -> AssemblerVerdict {
        if self.overflowed {
            self.overflowed = false;
            return AssemblerVerdict::TooLarge;
        }

        if matches!(stage, SshState::Clear(ClearStage { state: ClearState::VersionExchange, .. })) {
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

    pub fn clear(&mut self) {
        self.buffer.clear();
        self.overflowed = false;
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
    use crate::data_plane::packet_context::PacketId;
    use crate::dpi::stages::SshL4Stage;
    use crate::dpi::AppProto;
    use crate::l4::stage::{L4Outcome, L4Stage, TerminateReason};
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
        assembler.push(&cycle1[..split1]);
        v.push(assembler.take(&state));
        assembler.push(&cycle1[split1..2 * split1]);
        v.push(assembler.take(&state));
        assembler.push(&cycle1[2 * split1..3 * split1]);
        v.push(assembler.take(&state));
        let mut push4 = Vec::from(&cycle1[3 * split1..]);
        push4.extend_from_slice(&cycle2[..split2]);
        assembler.push(&push4);
        v.push(assembler.take(&state));
        assembler.push(&cycle2[split2..2 * split2]);
        v.push(assembler.take(&state));
        assembler.push(&cycle2[2 * split2..3 * split2]);
        v.push(assembler.take(&state));
        assembler.push(&cycle2[3 * split2..]);
        v.push(assembler.take(&state));

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
            a.push(&[*byte]);
            verdicts.push(a.take(&state));
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
            BufferingDisposition { packet: PacketAction::QueueAndHalt, unit: UnitStatus::Incomplete }
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
            SshState::PartiallyEncrypted(SshHost::Client)
        ));

        drive(&mut session, &mut ctx, Direction::Reply, &new_keys_bytes());
        assert!(matches!(session.state, SshState::Encrypted));

        let d = drive(&mut session, &mut ctx, Direction::Original, b"\x00\x01\x02\x03");
        assert_eq!(
            d,
            BufferingDisposition { packet: PacketAction::Pass, unit: UnitStatus::Complete }
        );
    }

    async fn drive_l4(
        stage: &mut SshL4Stage<StubZoneResolver>,
        ctx: &mut SessionContext,
        id: PacketId,
        dir: Direction,
        payload: &[u8],
    ) -> L4Outcome {
        stage.on_bytes(ctx, id, dir, 0, payload).await
    }

    #[tokio::test]
    async fn ssh_l4_stage_forwards_full_handshake() {
        let mut stage = SshL4Stage::new(mock_policy_retriever());
        let mut ctx = session_context();

        let id1 = PacketId::next();
        let id2 = PacketId::next();
        let id3 = PacketId::next();
        let id4 = PacketId::next();
        let id5 = PacketId::next();
        let id6 = PacketId::next();
        let id7 = PacketId::next();
        let id8 = PacketId::next();

        assert_eq!(
            drive_l4(&mut stage, &mut ctx, id1, Direction::Original, b"SSH-2.0-OpenSSH_8.9\r\n").await,
            L4Outcome::Forward(vec![id1])
        );
        assert_eq!(
            drive_l4(&mut stage, &mut ctx, id2, Direction::Reply, b"SSH-2.0-dropbear_2022.83\r\n").await,
            L4Outcome::Forward(vec![id2])
        );
        assert_eq!(
            drive_l4(&mut stage, &mut ctx, id3, Direction::Original, &kex_init_bytes()).await,
            L4Outcome::Forward(vec![id3])
        );
        assert_eq!(
            drive_l4(&mut stage, &mut ctx, id4, Direction::Reply, &kex_init_bytes()).await,
            L4Outcome::Forward(vec![id4])
        );
        assert_eq!(
            drive_l4(&mut stage, &mut ctx, id5, Direction::Original, &dh_init_bytes()).await,
            L4Outcome::Forward(vec![id5])
        );
        assert_eq!(
            drive_l4(&mut stage, &mut ctx, id6, Direction::Reply, &dh_reply_bytes()).await,
            L4Outcome::Forward(vec![id6])
        );
        assert_eq!(
            drive_l4(&mut stage, &mut ctx, id7, Direction::Original, &new_keys_bytes()).await,
            L4Outcome::Forward(vec![id7])
        );
        assert_eq!(
            drive_l4(&mut stage, &mut ctx, id8, Direction::Reply, &new_keys_bytes()).await,
            L4Outcome::Forward(vec![id8])
        );

        assert_eq!(ctx.application_protocol(), Some(AppProto::Ssh));
    }

    #[tokio::test]
    async fn ssh_l4_stage_forwards_after_encrypted() {
        let mut stage = SshL4Stage::new(mock_policy_retriever());
        let mut ctx = session_context();

        let ids: Vec<PacketId> = (0..8).map(|_| PacketId::next()).collect();

        assert_eq!(
            drive_l4(&mut stage, &mut ctx, ids[0], Direction::Original, b"SSH-2.0-OpenSSH_8.9\r\n").await,
            L4Outcome::Forward(vec![ids[0]])
        );
        assert_eq!(
            drive_l4(&mut stage, &mut ctx, ids[1], Direction::Reply, b"SSH-2.0-dropbear_2022.83\r\n").await,
            L4Outcome::Forward(vec![ids[1]])
        );
        assert_eq!(
            drive_l4(&mut stage, &mut ctx, ids[2], Direction::Original, &kex_init_bytes()).await,
            L4Outcome::Forward(vec![ids[2]])
        );
        assert_eq!(
            drive_l4(&mut stage, &mut ctx, ids[3], Direction::Reply, &kex_init_bytes()).await,
            L4Outcome::Forward(vec![ids[3]])
        );
        assert_eq!(
            drive_l4(&mut stage, &mut ctx, ids[4], Direction::Original, &dh_init_bytes()).await,
            L4Outcome::Forward(vec![ids[4]])
        );
        assert_eq!(
            drive_l4(&mut stage, &mut ctx, ids[5], Direction::Reply, &dh_reply_bytes()).await,
            L4Outcome::Forward(vec![ids[5]])
        );
        assert_eq!(
            drive_l4(&mut stage, &mut ctx, ids[6], Direction::Original, &new_keys_bytes()).await,
            L4Outcome::Forward(vec![ids[6]])
        );
        assert_eq!(
            drive_l4(&mut stage, &mut ctx, ids[7], Direction::Reply, &new_keys_bytes()).await,
            L4Outcome::Forward(vec![ids[7]])
        );

        let enc1 = PacketId::next();
        let enc2 = PacketId::next();

        assert_eq!(
            drive_l4(&mut stage, &mut ctx, enc1, Direction::Original, b"\x00\x01\x02").await,
            L4Outcome::Forward(vec![enc1])
        );
        assert_eq!(
            drive_l4(&mut stage, &mut ctx, enc2, Direction::Reply, b"\x00\x01\x02").await,
            L4Outcome::Forward(vec![enc2])
        );
    }

    #[tokio::test]
    async fn ssh_l4_stage_terminates_on_invalid_packet() {
        let mut stage = SshL4Stage::new(mock_policy_retriever());
        let mut ctx = session_context();

        let banner_id_1 = PacketId::next();
        let banner_id_2 = PacketId::next();
        let bad_id = PacketId::next();

        assert_eq!(
            drive_l4(&mut stage, &mut ctx, banner_id_1, Direction::Original, b"SSH-2.0-OpenSSH_8.9\r\n").await,
            L4Outcome::Forward(vec![banner_id_1])
        );
        assert_eq!(
            drive_l4(&mut stage, &mut ctx, banner_id_2, Direction::Reply, b"SSH-2.0-dropbear_2022.83\r\n").await,
            L4Outcome::Forward(vec![banner_id_2])
        );

        let bad_packet: &[u8] = &[
            0x00, 0x00, 0x00, 0x08,
            0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
        ];

        assert_eq!(
            drive_l4(&mut stage, &mut ctx, bad_id, Direction::Original, bad_packet).await,
            L4Outcome::Terminate {
                reason: TerminateReason::StageRequested,
                reset: true,
            }
        );
    }

    #[test]
    fn interleaved_kexinit_segments_dont_mix_directions() {
        let mut session = SshSession::new(mock_policy_retriever());
        let mut ctx = session_context();

        drive(&mut session, &mut ctx, Direction::Original, b"SSH-2.0-OpenSSH_8.9\r\n");

        let kex = kex_init_bytes();
        let mid = kex.len() / 2;
        drive(&mut session, &mut ctx, Direction::Original, &kex[..mid]);
        drive(&mut session, &mut ctx, Direction::Reply, b"SSH-2.0-dropbear_2022.83\r\n");
        drive(&mut session, &mut ctx, Direction::Original, &kex[mid..]);
        drive(&mut session, &mut ctx, Direction::Reply, &kex);

        assert!(matches!(
            session.state,
            SshState::Clear(ClearStage {
                state: ClearState::KeyExchange,
                expected_host: SshHost::Client,
            })
        ));
    }

    #[test]
    fn interleaved_dh_segments_dont_mix_directions() {
        let mut session = SshSession::new(mock_policy_retriever());
        let mut ctx = session_context();

        drive(&mut session, &mut ctx, Direction::Original, b"SSH-2.0-OpenSSH_8.9\r\n");
        drive(&mut session, &mut ctx, Direction::Reply, b"SSH-2.0-dropbear_2022.83\r\n");
        drive(&mut session, &mut ctx, Direction::Original, &kex_init_bytes());
        drive(&mut session, &mut ctx, Direction::Reply, &kex_init_bytes());

        let init = dh_init_bytes();
        let reply = dh_reply_bytes();
        let init_mid = init.len() / 2;
        let reply_mid = reply.len() / 2;
        drive(&mut session, &mut ctx, Direction::Original, &init[..init_mid]);
        drive(&mut session, &mut ctx, Direction::Reply, &reply[..reply_mid]);
        drive(&mut session, &mut ctx, Direction::Original, &init[init_mid..]);
        drive(&mut session, &mut ctx, Direction::Reply, &reply[reply_mid..]);

        assert!(matches!(
            session.state,
            SshState::Clear(ClearStage {
                state: ClearState::NewKeys,
                expected_host: SshHost::Client,
            })
        ));
    }

    #[test]
    fn server_coalesces_dh_reply_new_keys_and_encrypted() {
        let mut session = SshSession::new(mock_policy_retriever());
        let mut ctx = session_context();

        drive(&mut session, &mut ctx, Direction::Original, b"SSH-2.0-OpenSSH_8.9\r\n");
        drive(&mut session, &mut ctx, Direction::Reply, b"SSH-2.0-dropbear_2022.83\r\n");
        drive(&mut session, &mut ctx, Direction::Original, &kex_init_bytes());
        drive(&mut session, &mut ctx, Direction::Reply, &kex_init_bytes());
        drive(&mut session, &mut ctx, Direction::Original, &dh_init_bytes());

        assert!(matches!(
            session.state,
            SshState::Clear(ClearStage { state: ClearState::KeyExchange, expected_host: SshHost::Server })
        ));

        let mut payload = dh_reply_bytes();
        payload.extend_from_slice(&new_keys_bytes());
        payload.extend_from_slice(b"\x00\x01\x02\x03");
        let d = drive(&mut session, &mut ctx, Direction::Reply, &payload);
        assert_eq!(d, BufferingDisposition { packet: PacketAction::Pass, unit: UnitStatus::Complete });
        assert!(matches!(session.state, SshState::PartiallyEncrypted(SshHost::Server)));
    }

    #[test]
    fn client_coalesces_new_keys_and_encrypted_after_server_encrypted() {
        let mut session = SshSession::new(mock_policy_retriever());
        let mut ctx = session_context();

        drive(&mut session, &mut ctx, Direction::Original, b"SSH-2.0-OpenSSH_8.9\r\n");
        drive(&mut session, &mut ctx, Direction::Reply, b"SSH-2.0-dropbear_2022.83\r\n");
        drive(&mut session, &mut ctx, Direction::Original, &kex_init_bytes());
        drive(&mut session, &mut ctx, Direction::Reply, &kex_init_bytes());
        drive(&mut session, &mut ctx, Direction::Original, &dh_init_bytes());

        let mut server_payload = dh_reply_bytes();
        server_payload.extend_from_slice(&new_keys_bytes());
        drive(&mut session, &mut ctx, Direction::Reply, &server_payload);
        assert!(matches!(session.state, SshState::PartiallyEncrypted(SshHost::Server)));

        let mut client_payload = new_keys_bytes();
        client_payload.extend_from_slice(b"\x00\x01\x02\x03");
        let d = drive(&mut session, &mut ctx, Direction::Original, &client_payload);
        assert_eq!(d, BufferingDisposition { packet: PacketAction::Pass, unit: UnitStatus::Complete });
        assert!(matches!(session.state, SshState::Encrypted));

        let d = drive(&mut session, &mut ctx, Direction::Original, b"\x00\x01\x02\x03");
        assert_eq!(d, BufferingDisposition { packet: PacketAction::Pass, unit: UnitStatus::Complete });
        let d = drive(&mut session, &mut ctx, Direction::Reply, b"\x00\x01\x02\x03");
        assert_eq!(d, BufferingDisposition { packet: PacketAction::Pass, unit: UnitStatus::Complete });
    }
}
