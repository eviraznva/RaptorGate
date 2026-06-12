use std::sync::Arc;

use ssh_parser::{parse_ssh_identification, parse_ssh_packet};

use crate::{
    conntrack::tuple::Direction,
    data_plane::packet_context::PacketId,
    dpi::{AppProto, smtp::{BufferingDisposition, PacketAction, UnitStatus}},
    l4::SessionContext,
    policy::{retriever::PolicyRetriever, SshPolicy},
    zones::resolver::ZoneResolver,
};

pub mod policy;

use self::policy::{
    compute_negotiated, first_ssh_string, OwnedKexInit, SshBannerInfo, SshDisconnectInfo, SshHost,
    SshHostKeyInfo, SshMetadata,
};

use tracing;

const MAX_HANDSHAKE_PACKET_SIZE: usize = 64 * 1024;

impl From<Direction> for SshHost {
    fn from(dir: Direction) -> Self {
        match dir {
            Direction::Original => SshHost::Client,
            Direction::Reply => SshHost::Server,
        }
    }
}

#[derive(Debug, Clone)]
pub(crate) enum SshState {
    Clear(ClearState),
    Encrypted,
}

#[derive(Debug, Clone)]
pub(crate) enum ClearState {
    VersionExchange,
    AlgorithmNegotiation,
    KeyExchange,
}

#[derive(Debug, Clone)]
pub(crate) enum SshPacket {
    Disconnect,
    Ignore,
    Unimplemented(u32),
    Debug,
    ServiceRequest,
    ServiceAccept,
    KeyExchange,
    NewKeys,
    DiffieHellmanInit,
    DiffieHellmanReply,
    ExtInfo,
    KexMethod(u8),
}

impl<'a> From<&'a ssh_parser::SshPacket<'a>> for SshPacket {
    fn from(p: &'a ssh_parser::SshPacket<'a>) -> Self {
        match p {
            ssh_parser::SshPacket::Disconnect(_) => SshPacket::Disconnect,
            ssh_parser::SshPacket::Ignore(_) => SshPacket::Ignore,
            ssh_parser::SshPacket::Unimplemented(n) => SshPacket::Unimplemented(*n),
            ssh_parser::SshPacket::Debug(_) => SshPacket::Debug,
            ssh_parser::SshPacket::ServiceRequest(_) => SshPacket::ServiceRequest,
            ssh_parser::SshPacket::ServiceAccept(_) => SshPacket::ServiceAccept,
            ssh_parser::SshPacket::KeyExchange(_) => SshPacket::KeyExchange,
            ssh_parser::SshPacket::NewKeys => SshPacket::NewKeys,
            ssh_parser::SshPacket::DiffieHellmanInit(_) => SshPacket::DiffieHellmanInit,
            ssh_parser::SshPacket::DiffieHellmanReply(_) => SshPacket::DiffieHellmanReply,
        }
    }
}

impl SshState {
    fn advance_version(state: &mut SshState) -> Result<(), ()> {
        match state {
            SshState::Clear(ClearState::VersionExchange) => {
                *state = SshState::Clear(ClearState::AlgorithmNegotiation);
                Ok(())
            }
            _ => Err(()),
        }
    }

    fn advance_with_packet(state: &mut SshState, packet: &SshPacket) -> Result<(), ()> {
        let transition = match state {
            SshState::Clear(ClearState::AlgorithmNegotiation) => match packet {
                SshPacket::KeyExchange => Some(SshState::Clear(ClearState::KeyExchange)),
                SshPacket::ExtInfo => None,
                SshPacket::Disconnect | SshPacket::Ignore | SshPacket::Unimplemented(_) | SshPacket::Debug => None,
                _ => return Err(()),
            },
            SshState::Clear(ClearState::KeyExchange) => match packet {
                SshPacket::NewKeys => Some(SshState::Encrypted),
                SshPacket::DiffieHellmanInit | SshPacket::DiffieHellmanReply | SshPacket::KexMethod(_) => None,
                SshPacket::KeyExchange => None,
                SshPacket::ExtInfo => None,
                SshPacket::Disconnect | SshPacket::Ignore | SshPacket::Unimplemented(_) | SshPacket::Debug => None,
                _ => return Err(()),
            },
            _ => return Err(()),
        };
        if let Some(s) = transition {
            *state = s;
        }
        Ok(())
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

impl<'a> From<ssh_parser::SshVersion<'a>> for SshVersionOwned {
    fn from(v: ssh_parser::SshVersion<'a>) -> Self {
        Self {
            proto: v.proto.to_vec(),
            software: v.software.to_vec(),
            comments: v.comments.map(Vec::from),
        }
    }
}

pub(crate) struct SshSession<ZR>
where
    ZR: ZoneResolver,
{
    pub(crate) client_state: SshState,
    pub(crate) server_state: SshState,
    pub(crate) client_assembler: SshPacketAssembler,
    pub(crate) server_assembler: SshPacketAssembler,
    confirmed_ssh: bool,
    policy_retriever: Arc<PolicyRetriever<ZR>>,
    ssh_policies: Option<Vec<SshPolicy>>,
    first_kexinit: Option<(SshHost, OwnedKexInit)>,
}

impl<ZR> SshSession<ZR>
where
    ZR: ZoneResolver,
{
    pub fn new(policy_retriever: Arc<PolicyRetriever<ZR>>) -> Self {
        SshSession {
            client_state: SshState::Clear(ClearState::VersionExchange),
            server_state: SshState::Clear(ClearState::VersionExchange),
            client_assembler: SshPacketAssembler::new(),
            server_assembler: SshPacketAssembler::new(),
            confirmed_ssh: false,
            policy_retriever,
            ssh_policies: None,
            first_kexinit: None,
        }
    }

    fn ensure_policies(&mut self, ctx: &SessionContext) {
        if self.ssh_policies.is_none() {
            let tuple = &ctx.entry().original;
            self.ssh_policies = Some(
                self.policy_retriever
                    .retrieve_ssh(tuple.src_ip, tuple.dst_ip),
            );
        }
    }

    fn policies_allow<M: SshMetadata>(&self, meta: &M) -> bool {
        let policies = self.ssh_policies.as_deref().unwrap_or(&[]);
        SshPolicy::evaluate_policies(policies, meta)
    }

    fn host_state(&self, host: SshHost) -> &SshState {
        match host {
            SshHost::Client => &self.client_state,
            SshHost::Server => &self.server_state,
        }
    }

    fn host_state_mut(&mut self, host: SshHost) -> &mut SshState {
        match host {
            SshHost::Client => &mut self.client_state,
            SshHost::Server => &mut self.server_state,
        }
    }

    fn host_assembler(&mut self, host: SshHost) -> &mut SshPacketAssembler {
        match host {
            SshHost::Client => &mut self.client_assembler,
            SshHost::Server => &mut self.server_assembler,
        }
    }

    fn handle_complete_message(
        &mut self,
        ctx: &mut SessionContext,
        body: Vec<u8>,
        host: SshHost,
    ) -> Result<bool, ()> {
        if !self.confirmed_ssh {
            self.confirmed_ssh = true;
            ctx.set_application_protocol(AppProto::Ssh);
        }

        self.ensure_policies(ctx);

        if matches!(self.host_state(host), SshState::Clear(ClearState::VersionExchange)) {
            let (_, (_, version)) = parse_ssh_identification(&body).map_err(|_| {
                tracing::info!("SSH ERROR invalid version line from {host:?}");
            })?;
            let banner = SshBannerInfo {
                host,
                proto_version: version.proto.to_vec(),
                software: version.software.to_vec(),
                comments: version.comments.map(|c| c.to_vec()),
            };
            if !self.policies_allow(&banner) {
                tracing::info!("SSH POLICY denied banner from {host:?}");
                return Ok(false);
            }
            SshState::advance_version(self.host_state_mut(host)).map_err(|_| {
                tracing::info!("SSH ERROR unexpected version from {host:?}");
            })?;
            return Ok(true);
        }

        if body.len() < 2 {
            return Err(());
        }
        let msg_type = body[1];
        let packet = match msg_type {
            1..=6 | 20 | 21 | 30 | 31 => {
                let mut wire = Vec::with_capacity(4 + body.len());
                wire.extend_from_slice(&(body.len() as u32).to_be_bytes());
                wire.extend_from_slice(&body);
                let (_, (parsed, _)) = parse_ssh_packet(&wire).map_err(|_| {
                    tracing::info!(
                        "SSH ERROR invalid packet body (len={}) from {host:?}, msg_type={msg_type}",
                        body.len()
                    );
                })?;
                if !self.evaluate_parsed_packet(&parsed, host)? {
                    return Ok(false);
                }
                SshPacket::from(&parsed)
            }
            7 => SshPacket::ExtInfo,
            32..=49 => SshPacket::KexMethod(msg_type),
            _ => {
                tracing::info!(
                    "SSH ERROR unknown msg_type {msg_type} from {host:?} in state={:?}",
                    self.host_state(host)
                );
                return Err(());
            }
        };
        let state = self.host_state(host).clone();
        SshState::advance_with_packet(self.host_state_mut(host), &packet).map_err(|_| {
            tracing::info!(
                "SSH ERROR unexpected packet {packet:?} from {host:?} in state={state:?}"
            );
        })?;
        Ok(true)
    }

    fn evaluate_parsed_packet(
        &mut self,
        parsed: &ssh_parser::SshPacket<'_>,
        host: SshHost,
    ) -> Result<bool, ()> {
        match parsed {
            ssh_parser::SshPacket::KeyExchange(kex) => {
                let owned = OwnedKexInit::from_kexinit(kex);
                if let Some((first_host, first_kex)) = self.first_kexinit.take() {
                    let (client_kex, server_kex) = if first_host == SshHost::Client {
                        (first_kex, owned)
                    } else {
                        (owned, first_kex)
                    };
                    let negotiated = compute_negotiated(&client_kex, &server_kex);
                    if !self.policies_allow(&negotiated) {
                        tracing::info!("SSH POLICY denied negotiated algorithms");
                        return Ok(false);
                    }
                } else {
                    self.first_kexinit = Some((host, owned));
                }
            }
            ssh_parser::SshPacket::DiffieHellmanReply(reply) => {
                if let Some(key_type) = first_ssh_string(reply.pubkey_and_cert) {
                    let info = SshHostKeyInfo {
                        key_type: key_type.to_vec(),
                    };
                    if !self.policies_allow(&info) {
                        tracing::info!("SSH POLICY denied host key type");
                        return Ok(false);
                    }
                }
            }
            ssh_parser::SshPacket::Disconnect(d) => {
                let info = SshDisconnectInfo {
                    reason_code: d.reason_code,
                };
                if !self.policies_allow(&info) {
                    tracing::info!("SSH POLICY denied disconnect reason {}", d.reason_code);
                    return Ok(false);
                }
            }
            _ => {}
        }
        Ok(true)
    }

    pub(crate) fn process_bytes(
        &mut self,
        ctx: &mut SessionContext,
        packet_id: PacketId,
        dir: Direction,
        payload: &[u8],
    ) -> BufferingDisposition {
        let host = SshHost::from(dir);

        if matches!(self.host_state(host), SshState::Encrypted) {
            tracing::info!("SSH FORWARDED encrypted data from {host:?}");
            return BufferingDisposition { packet: PacketAction::Pass, unit: UnitStatus::Complete };
        }

        let payload_len = payload.len();
        self.host_assembler(host).push(payload);
        let buffer_len = self.host_assembler(host).buffer_len();
        tracing::trace!(
            "SSH ASSEMBLER pushed {payload_len} bytes to {host:?}, buffer now {buffer_len} bytes, state={:?}",
            self.host_state(host),
        );

        loop {
            let state = self.host_state(host).clone();
            let verdict = self.host_assembler(host).take(&state);
            match verdict {
                AssemblerVerdict::NeedMore => {
                    tracing::info!("SSH FORWARDED incomplete message from {host:?}");
                    return BufferingDisposition {
                        packet: PacketAction::QueueAndHalt,
                        unit: UnitStatus::Incomplete,
                    };
                }
                AssemblerVerdict::TooLarge | AssemblerVerdict::Invalid => {
                    if !self.confirmed_ssh {
                        tracing::info!("SSH FORWARDED non-ssh data from {host:?}");
                        return BufferingDisposition {
                            packet: PacketAction::Pass,
                            unit: UnitStatus::Complete,
                        };
                    }
                    let hexdump: String = self.host_assembler(host).buffer_dump();
                    tracing::info!(
                        "SSH ERROR invalid/too-large from {host:?} after confirmed ssh, state={state:?} hex={hexdump}"
                    );
                    return BufferingDisposition {
                        packet: PacketAction::Drop,
                        unit: UnitStatus::Complete,
                    };
                }
                AssemblerVerdict::PacketComplete(body) => {
                    match self.handle_complete_message(ctx, body, host) {
                        Ok(false) => {
                            tracing::info!("SSH POLICY denied {host:?}, state={state:?}");
                            return BufferingDisposition {
                                packet: PacketAction::Drop,
                                unit: UnitStatus::Complete,
                            };
                        }
                        Err(()) => {
                            tracing::info!(
                                "SSH ERROR handle_complete_message failed for {host:?}, state={state:?}"
                            );
                            return BufferingDisposition {
                                packet: PacketAction::Drop,
                                unit: UnitStatus::Complete,
                            };
                        }
                        Ok(true) => {}
                    }
                    if matches!(self.host_state(host), SshState::Encrypted) {
                        tracing::info!("SSH FORWARDED encrypted complete message from {host:?}");
                        self.host_assembler(host).clear();
                        return BufferingDisposition {
                            packet: PacketAction::Pass,
                            unit: UnitStatus::Complete,
                        };
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

    pub fn buffer_len(&self) -> usize {
        self.buffer.len()
    }

    pub fn push(&mut self, payload: &[u8]) {
        if self.overflowed {
            tracing::info!("SSH ERROR assembler overflowed, dropping {} bytes", payload.len());
            return;
        }
        if self.buffer.len() + payload.len() > MAX_HANDSHAKE_PACKET_SIZE {
            tracing::info!("SSH ERROR assembler buffer would exceed max size (buffer={}, payload={}), clearing", self.buffer.len(), payload.len());
            self.buffer.clear();
            self.overflowed = true;
            return;
        }
        self.buffer.extend_from_slice(payload);
    }

    pub fn take(&mut self, stage: &SshState) -> AssemblerVerdict {
        if self.overflowed {
            tracing::info!("SSH ERROR assembler returning TooLarge from overflowed state");
            self.overflowed = false;
            return AssemblerVerdict::TooLarge;
        }

        if matches!(stage, SshState::Clear(ClearState::VersionExchange)) {
            if let Some(pos) = self.buffer.iter().position(|&b| b == b'\n') {
                let line: Vec<u8> = self.buffer.drain(..pos + 1).collect();
                return AssemblerVerdict::PacketComplete(line);
            }
            tracing::trace!(
                "SSH ASSEMBLER NeedMore (version): buffer.len={}",
                self.buffer.len()
            );
            return AssemblerVerdict::NeedMore;
        }

        if self.buffer.len() < 4 {
            tracing::trace!(
                "SSH ASSEMBLER NeedMore (no header): buffer.len={}",
                self.buffer.len()
            );
            return AssemblerVerdict::NeedMore;
        }

        let declared_length = u32::from_be_bytes(self.buffer[..4].try_into().unwrap_or([0, 0, 0, 0]));

        if declared_length > MAX_HANDSHAKE_PACKET_SIZE as u32 || declared_length == 0 {
            tracing::info!("SSH ERROR invalid declared length {} from buffer len={} stage={stage:?}", declared_length, self.buffer.len());
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
            tracing::trace!(
                "SSH ASSEMBLER NeedMore (partial): declared_length={} buffer.len={} need={}",
                declared_length,
                self.buffer.len(),
                4 + declared_length,
            );
            AssemblerVerdict::NeedMore
        }
    }

    pub fn clear(&mut self) {
        self.buffer.clear();
        self.overflowed = false;
    }

    pub fn buffer_dump(&self) -> String {
        let n = self.buffer.len().min(32);
        self.buffer[..n]
            .iter()
            .map(|b| format!("{:02x}", b))
            .collect::<Vec<_>>()
            .join(" ")
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
    use crate::policy::retriever::PolicyRetriever;
    use crate::policy::{Policy, PolicyId, SshPolicy};
    use crate::rule_tree::{ArmEnd, MatchBuilder, MatchKind, Pattern, RuleTree, Verdict};
    use crate::zones::resolver::ZoneResolver;
    use crate::zones::{DefaultPolicy, DirectionalZonePairs, ResolvedZonePair, ZonePairId};

    fn in_clear(state: ClearState) -> SshState {
        SshState::Clear(state)
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

    fn mock_policy_retriever_with_ssh(policies: Vec<SshPolicy>) -> Arc<PolicyRetriever<StubZoneResolver>> {
        let zone_resolver = Arc::new(StubZoneResolver);
        let zone_pair_id = ZonePairId::from(Uuid::nil());
        let mut policy_map = HashMap::new();
        for (index, ssh_policy) in policies.into_iter().enumerate() {
            let policy_id = PolicyId::from(Uuid::from_u128(3000 + index as u128));
            policy_map.insert(
                policy_id,
                Policy {
                    name: format!("ssh-test-policy-{index}"),
                    zone_pair_id: zone_pair_id.clone(),
                    priority: index as u32,
                    rule_tree: RuleTree::new(
                        MatchBuilder::with_arm(
                            MatchKind::IpVer,
                            Pattern::Wildcard,
                            ArmEnd::Verdict(Verdict::Allow),
                        )
                        .build()
                        .unwrap(),
                    ),
                    smtp_policy: crate::policy::SmtpPolicy::default(),
                    ssh_policy,
                },
            );
        }
        let policy_provider = Arc::new(DiskPolicyProvider::from_policies(
            policy_map,
            PathBuf::from("/tmp"),
        ));
        Arc::new(PolicyRetriever::new(zone_resolver, policy_provider))
    }

    fn mock_policy_retriever() -> Arc<PolicyRetriever<StubZoneResolver>> {
        mock_policy_retriever_with_ssh(vec![SshPolicy::permissive()])
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
            in_clear(ClearState::VersionExchange),
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
            in_clear(ClearState::VersionExchange),
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
        let cycle1 = vec![b'X'; 992_052];
        let cycle2 = vec![b'X'; 992_052];
        let v = run_two_cycles(
            &mut a,
            &cycle1,
            &cycle2,
            in_clear(ClearState::VersionExchange),
        );
        for (i, verdict) in v.iter().enumerate() {
            assert!(
                matches!(verdict, AssemblerVerdict::TooLarge),
                "verdict {i} expected TooLarge"
            );
        }
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
            in_clear(ClearState::AlgorithmNegotiation),
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
            in_clear(ClearState::AlgorithmNegotiation),
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
            in_clear(ClearState::AlgorithmNegotiation),
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
        let cycle1 = vec![b'X'; 992_052];
        let cycle2 = vec![b'X'; 992_052];
        let v = run_two_cycles(
            &mut a,
            &cycle1,
            &cycle2,
            in_clear(ClearState::AlgorithmNegotiation),
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
        let state = in_clear(ClearState::AlgorithmNegotiation);
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
            session.client_state,
            SshState::Clear(ClearState::VersionExchange)
        ));
        assert!(matches!(
            session.server_state,
            SshState::Clear(ClearState::VersionExchange)
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
            session.client_state,
            SshState::Clear(ClearState::AlgorithmNegotiation)
        ));
        assert!(matches!(
            session.server_state,
            SshState::Clear(ClearState::VersionExchange)
        ));

        drive(
            &mut session,
            &mut ctx,
            Direction::Reply,
            b"SSH-2.0-dropbear_2022.83\r\n",
        );
        assert!(matches!(
            session.client_state,
            SshState::Clear(ClearState::AlgorithmNegotiation)
        ));
        assert!(matches!(
            session.server_state,
            SshState::Clear(ClearState::AlgorithmNegotiation)
        ));

        drive(&mut session, &mut ctx, Direction::Original, &kex_init_bytes());
        assert!(matches!(
            session.client_state,
            SshState::Clear(ClearState::KeyExchange)
        ));
        assert!(matches!(
            session.server_state,
            SshState::Clear(ClearState::AlgorithmNegotiation)
        ));

        drive(&mut session, &mut ctx, Direction::Reply, &kex_init_bytes());
        assert!(matches!(
            session.client_state,
            SshState::Clear(ClearState::KeyExchange)
        ));
        assert!(matches!(
            session.server_state,
            SshState::Clear(ClearState::KeyExchange)
        ));

        drive(&mut session, &mut ctx, Direction::Original, &dh_init_bytes());
        assert!(matches!(
            session.client_state,
            SshState::Clear(ClearState::KeyExchange)
        ));
        assert!(matches!(
            session.server_state,
            SshState::Clear(ClearState::KeyExchange)
        ));

        drive(&mut session, &mut ctx, Direction::Reply, &dh_reply_bytes());
        assert!(matches!(
            session.client_state,
            SshState::Clear(ClearState::KeyExchange)
        ));
        assert!(matches!(
            session.server_state,
            SshState::Clear(ClearState::KeyExchange)
        ));

        drive(&mut session, &mut ctx, Direction::Original, &new_keys_bytes());
        assert!(matches!(session.client_state, SshState::Encrypted));
        assert!(matches!(
            session.server_state,
            SshState::Clear(ClearState::KeyExchange)
        ));

        drive(&mut session, &mut ctx, Direction::Reply, &new_keys_bytes());
        assert!(matches!(session.client_state, SshState::Encrypted));
        assert!(matches!(session.server_state, SshState::Encrypted));

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
    async fn ssh_l4_stage_terminates_on_default_deny_policy_set() {
        let empty_retriever = Arc::new(PolicyRetriever::new(
            Arc::new(StubZoneResolver),
            Arc::new(DiskPolicyProvider::from_policies(
                HashMap::new(),
                PathBuf::from("/tmp"),
            )),
        ));
        let mut stage = SshL4Stage::new(empty_retriever);
        let mut ctx = session_context();
        let banner_id = PacketId::next();

        assert_eq!(
            drive_l4(
                &mut stage,
                &mut ctx,
                banner_id,
                Direction::Original,
                b"SSH-2.0-OpenSSH_8.9\r\n",
            )
            .await,
            L4Outcome::Terminate {
                reason: TerminateReason::StageRequested,
                reset: true,
            }
        );
    }

    fn kex_init_with_algs(kex: &[&str]) -> Vec<u8> {
        let list = kex.join(",");
        let mut body = vec![4u8, 20];
        body.extend_from_slice(&[0u8; 16]);
        body.extend_from_slice(&(list.len() as u32).to_be_bytes());
        body.extend_from_slice(list.as_bytes());
        for _ in 0..9 {
            body.extend_from_slice(&0u32.to_be_bytes());
        }
        body.push(0);
        body.extend_from_slice(&[0u8; 4]);
        body.extend_from_slice(&[0u8; 4]);
        let mut wire = Vec::with_capacity(4 + body.len());
        wire.extend_from_slice(&(body.len() as u32).to_be_bytes());
        wire.extend_from_slice(&body);
        wire
    }

    #[tokio::test]
    async fn ssh_l4_stage_terminates_when_negotiated_kex_denied() {
        let deny_policy = SshPolicy {
            kex: vec![crate::policy::SshMatch {
                regex: regex::bytes::Regex::new("curve25519-sha256").unwrap(),
                on_match: crate::policy::SshMatchAction::Deny,
            }],
            ..SshPolicy::default()
        };
        let mut stage = SshL4Stage::new(mock_policy_retriever_with_ssh(vec![deny_policy]));
        let mut ctx = session_context();

        drive_l4(
            &mut stage,
            &mut ctx,
            PacketId::next(),
            Direction::Original,
            b"SSH-2.0-OpenSSH_8.9\r\n",
        )
        .await;
        drive_l4(
            &mut stage,
            &mut ctx,
            PacketId::next(),
            Direction::Reply,
            b"SSH-2.0-dropbear_2022.83\r\n",
        )
        .await;
        drive_l4(
            &mut stage,
            &mut ctx,
            PacketId::next(),
            Direction::Original,
            &kex_init_with_algs(&["curve25519-sha256", "diffie-hellman-group14-sha256"]),
        )
        .await;
        let id = PacketId::next();
        assert_eq!(
            drive_l4(
                &mut stage,
                &mut ctx,
                id,
                Direction::Reply,
                &kex_init_with_algs(&["curve25519-sha256"]),
            )
            .await,
            L4Outcome::Terminate {
                reason: TerminateReason::StageRequested,
                reset: true,
            }
        );
    }

    #[tokio::test]
    async fn ssh_l4_stage_terminates_when_banner_denied() {
        let deny_policy = SshPolicy {
            client_software: vec![crate::policy::SshMatch {
                regex: regex::bytes::Regex::new("dropbear_.*").unwrap(),
                on_match: crate::policy::SshMatchAction::Deny,
            }],
            ..SshPolicy::default()
        };
        let mut stage = SshL4Stage::new(mock_policy_retriever_with_ssh(vec![deny_policy]));
        let mut ctx = session_context();
        let banner_id = PacketId::next();

        assert_eq!(
            drive_l4(
                &mut stage,
                &mut ctx,
                banner_id,
                Direction::Original,
                b"SSH-2.0-dropbear_2022.83\r\n",
            )
            .await,
            L4Outcome::Terminate {
                reason: TerminateReason::StageRequested,
                reset: true,
            }
        );
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
            session.client_state,
            SshState::Clear(ClearState::KeyExchange)
        ));
        assert!(matches!(
            session.server_state,
            SshState::Clear(ClearState::KeyExchange)
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
            session.client_state,
            SshState::Clear(ClearState::KeyExchange)
        ));
        assert!(matches!(
            session.server_state,
            SshState::Clear(ClearState::KeyExchange)
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
            session.server_state,
            SshState::Clear(ClearState::KeyExchange)
        ));
        assert!(matches!(
            session.client_state,
            SshState::Clear(ClearState::KeyExchange)
        ));

        let mut payload = dh_reply_bytes();
        payload.extend_from_slice(&new_keys_bytes());
        payload.extend_from_slice(b"\x00\x01\x02\x03");
        let d = drive(&mut session, &mut ctx, Direction::Reply, &payload);
        assert_eq!(d, BufferingDisposition { packet: PacketAction::Pass, unit: UnitStatus::Complete });
        assert!(matches!(session.server_state, SshState::Encrypted));
        assert!(matches!(
            session.client_state,
            SshState::Clear(ClearState::KeyExchange)
        ));
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
        assert!(matches!(session.server_state, SshState::Encrypted));
        assert!(matches!(
            session.client_state,
            SshState::Clear(ClearState::KeyExchange)
        ));

        let mut client_payload = new_keys_bytes();
        client_payload.extend_from_slice(b"\x00\x01\x02\x03");
        let d = drive(&mut session, &mut ctx, Direction::Original, &client_payload);
        assert_eq!(d, BufferingDisposition { packet: PacketAction::Pass, unit: UnitStatus::Complete });
        assert!(matches!(session.client_state, SshState::Encrypted));
        assert!(matches!(session.server_state, SshState::Encrypted));

        let d = drive(&mut session, &mut ctx, Direction::Original, b"\x00\x01\x02\x03");
        assert_eq!(d, BufferingDisposition { packet: PacketAction::Pass, unit: UnitStatus::Complete });
        let d = drive(&mut session, &mut ctx, Direction::Reply, b"\x00\x01\x02\x03");
        assert_eq!(d, BufferingDisposition { packet: PacketAction::Pass, unit: UnitStatus::Complete });
    }

    #[test]
    fn client_newkeys_before_server_finishes_kex() {
        let mut session = SshSession::new(mock_policy_retriever());
        let mut ctx = session_context();

        drive(&mut session, &mut ctx, Direction::Original, b"SSH-2.0-OpenSSH_8.9\r\n");
        drive(&mut session, &mut ctx, Direction::Reply, b"SSH-2.0-dropbear_2022.83\r\n");
        drive(&mut session, &mut ctx, Direction::Original, &kex_init_bytes());
        drive(&mut session, &mut ctx, Direction::Original, &dh_init_bytes());

        // Client sends NEWKEYS before server has sent its KEXINIT/DH reply
        let d = drive(&mut session, &mut ctx, Direction::Original, &new_keys_bytes());
        assert_eq!(
            d,
            BufferingDisposition { packet: PacketAction::Pass, unit: UnitStatus::Complete }
        );
        assert!(matches!(session.client_state, SshState::Encrypted));
        assert!(matches!(
            session.server_state,
            SshState::Clear(ClearState::AlgorithmNegotiation)
        ));

        // Server can still progress
        drive(&mut session, &mut ctx, Direction::Reply, &kex_init_bytes());
        assert!(matches!(
            session.server_state,
            SshState::Clear(ClearState::KeyExchange)
        ));
        drive(&mut session, &mut ctx, Direction::Reply, &dh_reply_bytes());
        drive(&mut session, &mut ctx, Direction::Reply, &new_keys_bytes());
        assert!(matches!(session.server_state, SshState::Encrypted));
    }

    #[test]
    fn unsupported_kex_method_accepted() {
        let mut session = SshSession::new(mock_policy_retriever());
        let mut ctx = session_context();

        drive(&mut session, &mut ctx, Direction::Original, b"SSH-2.0-OpenSSH_8.9\r\n");
        drive(&mut session, &mut ctx, Direction::Reply, b"SSH-2.0-dropbear_2022.83\r\n");
        drive(&mut session, &mut ctx, Direction::Original, &kex_init_bytes());
        drive(&mut session, &mut ctx, Direction::Reply, &kex_init_bytes());

        // Build a minimal SSH packet with msg_type 32 (KEX method)
        let mut body = vec![4u8];      // padding_length
        body.push(32);                // msg_type = 32
        body.extend_from_slice(&[0u8; 4]); // padding
        let mut wire = Vec::with_capacity(4 + body.len());
        wire.extend_from_slice(&(body.len() as u32).to_be_bytes());
        wire.extend_from_slice(&body);

        let d = drive(&mut session, &mut ctx, Direction::Original, &wire);
        assert_eq!(
            d,
            BufferingDisposition {
                packet: PacketAction::QueueAndHalt,
                unit: UnitStatus::Incomplete
            }
        );
        assert!(matches!(
            session.client_state,
            SshState::Clear(ClearState::KeyExchange)
        ));

        // Complete the handshake normally
        drive(&mut session, &mut ctx, Direction::Original, &dh_init_bytes());
        drive(&mut session, &mut ctx, Direction::Reply, &dh_reply_bytes());
        drive(&mut session, &mut ctx, Direction::Original, &new_keys_bytes());
        drive(&mut session, &mut ctx, Direction::Reply, &new_keys_bytes());
        assert!(matches!(session.client_state, SshState::Encrypted));
        assert!(matches!(session.server_state, SshState::Encrypted));
    }

    #[test]
    fn ssh_msg_ext_info_accepted() {
        let mut session = SshSession::new(mock_policy_retriever());
        let mut ctx = session_context();

        drive(&mut session, &mut ctx, Direction::Original, b"SSH-2.0-OpenSSH_8.9\r\n");

        // Build ExtInfo packet (msg_type 7) during AlgorithmNegotiation
        let mut body = vec![4u8];      // padding_length
        body.push(7);                 // msg_type = 7 (EXT_INFO)
        body.extend_from_slice(&[0u8; 4]); // nr_extensions=0 as u32 + padding
        let mut wire = Vec::with_capacity(4 + body.len());
        wire.extend_from_slice(&(body.len() as u32).to_be_bytes());
        wire.extend_from_slice(&body);

        let d = drive(&mut session, &mut ctx, Direction::Original, &wire);
        assert_eq!(
            d,
            BufferingDisposition {
                packet: PacketAction::QueueAndHalt,
                unit: UnitStatus::Incomplete
            }
        );
        assert!(matches!(
            session.client_state,
            SshState::Clear(ClearState::AlgorithmNegotiation)
        ));

        // Complete handshake normally
        drive(&mut session, &mut ctx, Direction::Reply, b"SSH-2.0-dropbear_2022.83\r\n");
        drive(&mut session, &mut ctx, Direction::Original, &kex_init_bytes());
        drive(&mut session, &mut ctx, Direction::Reply, &kex_init_bytes());
        drive(&mut session, &mut ctx, Direction::Original, &dh_init_bytes());
        drive(&mut session, &mut ctx, Direction::Reply, &dh_reply_bytes());
        drive(&mut session, &mut ctx, Direction::Original, &new_keys_bytes());
        drive(&mut session, &mut ctx, Direction::Reply, &new_keys_bytes());
        assert!(matches!(session.client_state, SshState::Encrypted));
        assert!(matches!(session.server_state, SshState::Encrypted));
    }

    #[test]
    fn independent_assemblers_after_rename() {
        let mut session = SshSession::new(mock_policy_retriever());
        session.client_assembler.push(b"SSH-2.0-client\r\n");
        session.server_assembler.push(b"SSH-2.0-server\r\n");

        let v1 = session.client_assembler.take(&SshState::Clear(ClearState::VersionExchange));
        assert!(matches!(v1, AssemblerVerdict::PacketComplete(ref b) if b == b"SSH-2.0-client\r\n"));
        let v2 = session.server_assembler.take(&SshState::Clear(ClearState::VersionExchange));
        assert!(matches!(v2, AssemblerVerdict::PacketComplete(ref b) if b == b"SSH-2.0-server\r\n"));

        // After taking, both buffers are empty -- take returns NeedMore
        assert!(matches!(
            session.client_assembler.take(&SshState::Clear(ClearState::VersionExchange)),
            AssemblerVerdict::NeedMore
        ));
        assert!(matches!(
            session.server_assembler.take(&SshState::Clear(ClearState::VersionExchange)),
            AssemblerVerdict::NeedMore
        ));
    }
}
