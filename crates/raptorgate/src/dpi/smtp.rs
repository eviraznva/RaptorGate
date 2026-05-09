use dashmap::{DashMap, mapref::one::RefMut};
use etherparse::TransportSlice;
use smtp_proto::{request::receiver::{RequestReceiver, DataReceiver, BdatReceiver}, response::parser::ResponseReceiver};
use std::borrow::Cow;
use std::collections::VecDeque;
use std::sync::Arc;

use crate::data_plane::tcp_session_tracker::{EndpointIdentifier, TcpIdentifier};
use crate::dpi::smtp_policy_retriever::{SmtpPolicyRetriever, SmtpSessionPolicies};
use crate::events::{emit, Event, EventKind, SmtpSessionInfo};
use crate::interfaces::NetworkInterfaceMonitor;
use crate::policy::SmtpPolicy;
use crate::zones::resolver::{RoutingZoneResolver, ZoneResolver};

#[derive(Clone, Debug)]
pub(crate) struct TcpSeqSnapshot {
    pub endpoint: EndpointIdentifier,
    pub seq: u32,
    pub next_seq: u32,
}

pub(crate) struct SmtpPolicyEvaluator;

impl SmtpPolicyEvaluator {
    pub fn evaluate(session: &SmtpSession, policies: &[SmtpPolicy]) -> bool {
        if policies.is_empty() {
            return false;
        }

        let sender = session.current_sender.as_deref().unwrap_or("");
        let recipients = &session.current_recipients;
        let message = &session.current_message;

        for policy in policies {
            if !policy.sender.is_match(sender.as_bytes()) {
                return false;
            }

            for recipient in recipients {
                if !policy.recipient.is_match(recipient.as_bytes()) {
                    return false;
                }
            }

            if !policy.message.is_match(message) {
                return false;
            }
        }

        true
    }
}

#[derive(Clone, Copy, Debug, PartialEq)]
pub(crate) enum DataState {
    Await354,
    Collecting,
    Complete,
}

#[derive(Clone, Copy, Debug, PartialEq)]
pub(crate) enum BdatState {
    Collecting,
    Complete,
}

#[derive(Clone, Copy, Debug, PartialEq)]
pub(crate) enum SessionState {
    TcpEstabilished,
    GreetingReceived,
    Ready,
    EnvelopeOpen,
    ReciepientSet,
    Data(DataState),
    Bdat(BdatState),
}

#[derive(Clone, Copy, Debug, PartialEq)]
pub enum PacketAction {
    Pass,
    QueueAndHalt,
    Drop,
}

#[derive(Clone, Copy, Debug, PartialEq)]
pub enum UnitStatus {
    Incomplete,
    Complete,
}

#[derive(Clone, Copy, Debug, PartialEq)]
pub struct BufferingDisposition {
    pub packet: PacketAction,
    pub unit: UnitStatus,
}

pub(crate) enum SessionTransition<'a> {
    Request(smtp_proto::Request<Cow<'a, str>>),
    Response(smtp_proto::Response<String>),
    Greeting,
}

impl SessionState {
    fn transition(&self, event: SessionTransition) -> Result<Option<SessionState>, ()> {
        match event {
            SessionTransition::Greeting => match self {
                SessionState::TcpEstabilished => Ok(Some(SessionState::GreetingReceived)),
                _ => Err(()),
            },
            SessionTransition::Response(response) => {
                if response.code == 220 {
                    return self.transition(SessionTransition::Greeting);
                }
                if response.code == 354 && let SessionState::Data(DataState::Await354) = self {
                    return Ok(Some(SessionState::Data(DataState::Collecting)));
                }
                if response.code == 250 {
                    if let SessionState::Data(DataState::Complete) = self {
                        return Ok(Some(SessionState::Ready));
                    }
                    if let SessionState::Bdat(BdatState::Complete) = self {
                        return Ok(Some(SessionState::Ready));
                    }
                }
                Ok(None)
            }
            SessionTransition::Request(request) => {
                if matches!(self, SessionState::TcpEstabilished) {
                    return Err(());
                }
                match request {
                    smtp_proto::Request::Ehlo { .. }
                    | smtp_proto::Request::Lhlo { .. }
                    | smtp_proto::Request::Helo { .. } => match self {
                        SessionState::GreetingReceived
                        | SessionState::Ready
                        | SessionState::EnvelopeOpen
                        | SessionState::ReciepientSet => Ok(Some(SessionState::Ready)),
                        _ => Err(()),
                    },
                    smtp_proto::Request::Mail { .. } => match self {
                        SessionState::Ready => Ok(Some(SessionState::EnvelopeOpen)),
                        _ => Err(()),
                    },
                    smtp_proto::Request::Rcpt { .. } => match self {
                        SessionState::EnvelopeOpen => Ok(Some(SessionState::ReciepientSet)),
                        SessionState::ReciepientSet => Ok(None),
                        _ => Err(()),
                    },
                    smtp_proto::Request::Data | smtp_proto::Request::Bdat { .. } => match self {
                        SessionState::ReciepientSet => {
                            if matches!(request, smtp_proto::Request::Data) {
                                Ok(Some(SessionState::Data(DataState::Await354)))
                            } else {
                                Ok(Some(SessionState::Bdat(BdatState::Collecting)))
                            }
                        }
                        _ => Err(()),
                    },
                    smtp_proto::Request::Auth { .. } => {
                        tracing::info!("SMTP AUTH encountered; not yet supported");
                        Ok(None)
                    }
                    smtp_proto::Request::Noop { .. }
                    | smtp_proto::Request::Vrfy { .. }
                    | smtp_proto::Request::Expn { .. }
                    | smtp_proto::Request::Help { .. }
                    | smtp_proto::Request::Etrn { .. }
                    | smtp_proto::Request::Atrn { .. }
                    | smtp_proto::Request::Burl { .. } => Ok(None),
                    smtp_proto::Request::StartTls => {
                        tracing::warn!(
                            "TLS message encountered for SMTP, not supported, dropping session"
                        );
                        Err(())
                    }
                    smtp_proto::Request::Rset => Ok(Some(SessionState::Ready)),
                    smtp_proto::Request::Quit => Ok(None),
                }
            }
        }
    }
}

struct SmtpSession {
    state: SessionState,
    client: Option<EndpointIdentifier>,
    server: Option<EndpointIdentifier>,
    policies: Option<SmtpSessionPolicies>,
    request_receiver: RequestReceiver,
    response_receiver: ResponseReceiver,
    queued_packets: VecDeque<crate::data_plane::packet_context::PacketContext>,
    current_sender: Option<String>,
    current_recipients: Vec<String>,
    current_message: Vec<u8>,
    data_receiver: Option<DataReceiver>,
    bdat_receiver: Option<BdatReceiver>,
    client_seq: Option<TcpSeqSnapshot>,
    server_seq: Option<TcpSeqSnapshot>,
    rst_packets: Vec<Vec<u8>>,
}

impl SmtpSession {
    fn apply_transition(&mut self, event: SessionTransition<'_>) -> Result<(), ()> {
        let result = self.state.transition(event);
        self.apply_transition_result(result)
    }

    fn apply_transition_result(&mut self, result: Result<Option<SessionState>, ()>) -> Result<(), ()> {
        match result {
            Ok(Some(next)) => {
                if matches!(next, SessionState::Ready) {
                    if matches!(self.state, SessionState::Data(_)) {
                        self.data_receiver = None;
                        self.current_message.clear();
                    } else if matches!(self.state, SessionState::Bdat(_)) {
                        self.bdat_receiver = None;
                        self.current_message.clear();
                    }
                    if !matches!(self.state, SessionState::GreetingReceived | SessionState::TcpEstabilished) {
                        self.current_sender = None;
                        self.current_recipients.clear();
                        self.queued_packets.clear();
                    }
                }
                self.state = next;
                self.emit_state_changed();
                Ok(())
            }
            Ok(None) => {
                // self.emit_state_changed();
                Ok(())
            }
            Err(()) => Err(()),
        }
    }

    fn emit_state_changed(&self) {
        emit(Event::new(EventKind::SmtpSessionStateChanged {
            session: SmtpSessionInfo {
                client: self.client.clone(),
                server: self.server.clone(),
            },
            new_state: format!("{:?}", self.state),
        }));
    }
}

pub struct SmtpTracker<ZR = RoutingZoneResolver<NetworkInterfaceMonitor>> {
    pub(crate) sessions: DashMap<TcpIdentifier, SmtpSession>,
    policy_retriever: Arc<SmtpPolicyRetriever<ZR>>,
}

impl<ZR: ZoneResolver> SmtpTracker<ZR> {
    pub fn new(policy_retriever: Arc<SmtpPolicyRetriever<ZR>>) -> Self {
        SmtpTracker {
            sessions: DashMap::new(),
            policy_retriever,
        }
    }

    fn build_rst_packet(snapshot: &TcpSeqSnapshot, dst: &EndpointIdentifier) -> Option<Vec<u8>> {
        use std::net::IpAddr;
        use etherparse::{Ipv4Header, TcpHeader};

        let (src_ip, dst_ip) = match (snapshot.endpoint.ip, dst.ip) {
            (IpAddr::V4(src), IpAddr::V4(dst)) => (src, dst),
            _ => return None, // IPv6 not supported for now
        };

        let mut tcp_header = TcpHeader::new(
            u16::from(snapshot.endpoint.port),
            u16::from(dst.port),
            snapshot.next_seq,
            0,
        );
        tcp_header.rst = true;

        let ip_header = Ipv4Header::new(
            tcp_header.header_len_u16(),
            64,
            etherparse::IpNumber::TCP,
            src_ip.octets(),
            dst_ip.octets(),
        ).ok()?;

        let mut packet = Vec::new();
        packet.extend_from_slice(&[0u8; 14]); // Ethernet header placeholder
        ip_header.write(&mut packet).ok()?;
        tcp_header.write(&mut packet).ok()?;

        Some(packet)
    }

    pub fn get_session_policies(&self, id: &TcpIdentifier) -> Option<SmtpSessionPolicies> {
        self.sessions.get(id).and_then(|s| s.policies.clone())
    }
    
    pub fn enqueue_packet(&self, id: &TcpIdentifier, packet: crate::data_plane::packet_context::PacketContext) {
        if let Some(mut session) = self.sessions.get_mut(id) {
            session.queued_packets.push_back(packet);
        }
    }
    
    pub fn clear_queued_packets(&self, id: &TcpIdentifier) {
        if let Some(mut session) = self.sessions.get_mut(id) {
            session.queued_packets.clear();
        }
    }

    pub fn take_queued_packets(&self, id: &TcpIdentifier) -> VecDeque<crate::data_plane::packet_context::PacketContext> {
        if let Some(mut session) = self.sessions.get_mut(id) {
            std::mem::take(&mut session.queued_packets)
        } else {
            VecDeque::new()
        }
    }

    pub fn take_rst_packets(&self, id: &TcpIdentifier) -> Vec<Vec<u8>> {
        if let Some(mut session) = self.sessions.get_mut(id) {
            std::mem::take(&mut session.rst_packets)
        } else {
            Vec::new()
        }
    }

    /// Cleanup entrypoint for future TCP session removal integration.
    /// Called when a TCP session is removed to clean up associated SMTP state.
    pub fn on_tcp_session_removed(&self, id: &TcpIdentifier) {
        self.sessions.remove(id);
    }

    fn cleanup_session(&self, should_remove: bool, session: RefMut<'_, TcpIdentifier, SmtpSession>) {
        if should_remove {
            let key = session.key().clone();
            drop(session);
            self.sessions.remove(&key);
        }
    }

    #[allow(clippy::too_many_lines)]
    pub fn on_new_packet(
        &self,
        packet: TransportSlice,
        session: &TcpIdentifier,
        src: EndpointIdentifier,
        dst: EndpointIdentifier,
    ) -> BufferingDisposition {
        let TransportSlice::Tcp(tcp) = packet else { 
            return BufferingDisposition {
                packet: PacketAction::Pass,
                unit: UnitStatus::Incomplete,
            }
        };

        let mut session = self.sessions.entry(session.clone()).or_insert(SmtpSession {
            state: SessionState::TcpEstabilished,
            client: None,
            server: None,
            policies: None,
            request_receiver: RequestReceiver::default(),
            response_receiver: ResponseReceiver::default(),
            queued_packets: VecDeque::new(),
            current_sender: None,
            current_recipients: Vec::new(),
            current_message: Vec::new(),
            data_receiver: None,
            bdat_receiver: None,
            client_seq: None,
            server_seq: None,
            rst_packets: Vec::new(),
        });

        let mut should_remove = false; // need this since dashmap deadlocks when removing an entry without dropping
        let mut disposition = BufferingDisposition {
            packet: PacketAction::Pass,
            unit: UnitStatus::Incomplete,
        };

        // Update TCP sequence snapshot for this direction
        let payload_len = tcp.payload().len() as u32;
        let seq = tcp.sequence_number();
        let next_seq = seq.wrapping_add(payload_len);
        let snapshot = TcpSeqSnapshot {
            endpoint: src.clone(),
            seq,
            next_seq,
        };

        let is_from_client = session.client.as_ref().is_some_and(|c| *c == src);
        let is_from_server = session.server.as_ref().is_some_and(|s| *s == src);

        if is_from_client {
            session.client_seq = Some(snapshot);
        } else if is_from_server {
            session.server_seq = Some(snapshot);
        }

        if is_from_client || is_from_server {
            if is_from_server {
                disposition.packet = PacketAction::Pass;
                let mut bytes = tcp.payload().iter();
                loop {
                    match session.response_receiver.parse(&mut bytes) {
                        Ok(response) => {
                            if session.apply_transition(SessionTransition::Response(response)).is_err() {
                                should_remove = true;
                                break;
                            }
                            if matches!(session.state, SessionState::Data(DataState::Collecting)) {
                                session.data_receiver = Some(DataReceiver::new());
                            }
                            session.response_receiver.reset();
                        }
                        Err(smtp_proto::Error::NeedsMoreData { .. }) => break,
                        Err(_) => { should_remove = true; break; }
                    }
                }
            } else {
                disposition.packet = match session.state {
                    SessionState::Ready | SessionState::EnvelopeOpen | SessionState::ReciepientSet
                        | SessionState::Data(DataState::Await354 | DataState::Collecting) |
                        SessionState::Bdat(BdatState::Collecting) => PacketAction::QueueAndHalt,
                    _ => PacketAction::Pass,
                };
                
                let mut bytes = tcp.payload().iter();
                loop {
                    let current_state = session.state;
                    
                    if matches!(current_state, SessionState::Data(DataState::Collecting)) {
                        if let Some(mut receiver) = session.data_receiver.take() {
                            let completed = receiver.ingest(&mut bytes, &mut session.current_message);
                            if completed {
                                session.state = SessionState::Data(DataState::Complete);
                                session.emit_state_changed();
                                disposition.packet = PacketAction::QueueAndHalt;
                                disposition.unit = UnitStatus::Complete;
                            } else {
                                session.data_receiver = Some(receiver);
                            }
                        }
                        break;
                    }
                    
                    if matches!(current_state, SessionState::Bdat(BdatState::Collecting)) {
                        if let Some(mut receiver) = session.bdat_receiver.take() {
                            let completed = receiver.ingest(&mut bytes, &mut session.current_message);
                            if completed {
                                let is_last = receiver.is_last;
                                if is_last {
                                    session.state = SessionState::Bdat(BdatState::Complete);
                                    disposition.packet = PacketAction::QueueAndHalt;
                                    disposition.unit = UnitStatus::Complete;
                                } else {
                                    session.state = SessionState::ReciepientSet;
                                }
                            } else {
                                session.bdat_receiver = Some(receiver);
                            }
                        }
                        break;
                    }
                    
                    match session.request_receiver.ingest(&mut bytes) {
                        Ok(request) => {
                            tracing::debug!(request=?request, "Smtp Received received request");
                            let is_quit = matches!(&request, smtp_proto::Request::Quit);
                            let completes_buffered_unit = matches!(
                                &request,
                                smtp_proto::Request::Mail { .. }
                                    | smtp_proto::Request::Rcpt { .. }
                                    | smtp_proto::Request::Data
                                    | smtp_proto::Request::Rset
                            );
                            let bdat_params = match &request {
                                smtp_proto::Request::Bdat { chunk_size, is_last } => Some((*chunk_size, *is_last)),
                                _ => None,
                            };
                            
                            let sender = match &request {
                                smtp_proto::Request::Mail { from } => Some(from.address.to_string()),
                                _ => None,
                            };
                            
                            let recipient = match &request {
                                smtp_proto::Request::Rcpt { to } => Some(to.address.to_string()),
                                _ => None,
                            };
                            
                            let result = current_state.transition(SessionTransition::Request(request));
                            
                            if let Some(sender_addr) = sender {
                                session.current_sender = Some(sender_addr);
                            }
                            
                            if let Some(rcpt_addr) = recipient {
                                session.current_recipients.push(rcpt_addr);
                            }
                            
                            if let Some((chunk_size, is_last)) = bdat_params {
                                session.bdat_receiver = Some(BdatReceiver::new(chunk_size, is_last));
                            }

                            if session.apply_transition_result(result).is_err() {
                                should_remove = true;
                                break;
                            }

                            session.request_receiver = RequestReceiver::default();

                            if is_quit {
                                disposition.packet = PacketAction::Pass;
                                should_remove = true;
                            }

                            if disposition.packet == PacketAction::QueueAndHalt && completes_buffered_unit {
                                disposition.unit = UnitStatus::Complete;
                            }
                        }
                        Err(smtp_proto::Error::NeedsMoreData { .. }) => break,
                        Err(_) => {
                            if matches!(current_state, SessionState::Data(_) | SessionState::Bdat(_)) {
                                session.request_receiver = RequestReceiver::default();
                                break;
                            }
                            should_remove = true;
                            break;
                        }
                    }
                }
            }

            // Evaluate SMTP policies when buffered unit completes
            if disposition.unit == UnitStatus::Complete {
                if let Some(ref policies) = session.policies {
                    let allowed = SmtpPolicyEvaluator::evaluate(&session, &policies.client_to_server);
                    if !allowed {
                        // Denial: drop queued packets, generate RSTs, remove session
                        session.queued_packets.clear();
                        disposition.packet = PacketAction::Drop;
                        
                        // Generate RST packets
                        if let (Some(client_seq), Some(server_seq), Some(client), Some(server)) = 
                            (&session.client_seq, &session.server_seq, &session.client, &session.server) {
                            
                            let client_seq = client_seq.clone();
                            let server_seq = server_seq.clone();
                            let client = client.clone();
                            let server = server.clone();
                            
                            // RST toward server (using client sequence)
                            if let Some(rst_to_server) = Self::build_rst_packet(&client_seq, &server) {
                                session.rst_packets.push(rst_to_server);
                                tracing::debug!("Generated RST toward server");
                            }
                            
                            // RST toward client (using server sequence)
                            if let Some(rst_to_client) = Self::build_rst_packet(&server_seq, &client) {
                                session.rst_packets.push(rst_to_client);
                                tracing::debug!("Generated RST toward client");
                            }
                        }
                        
                        should_remove = true;
                    }
                }
            }

            self.cleanup_session(should_remove, session);
            return disposition;
        }

        let mut response_bytes = tcp.payload().iter();
        match session.response_receiver.parse(&mut response_bytes) {
            Ok(response) => {
                tracing::debug!(response=%response, "Smtp Received received response");

                session.server = Some(src.clone());
                session.client = Some(dst.clone());
                session.policies = Some(self.policy_retriever.retrieve(dst.ip, src.ip));
                session.request_receiver = RequestReceiver::default();
                if session.apply_transition(SessionTransition::Response(response)).is_err() {
                    should_remove = true;
                }
                session.response_receiver.reset();
            }
            Err(smtp_proto::Error::NeedsMoreData { .. }) => {}
            Err(_) => {
                let mut request_bytes = tcp.payload().iter();
                let current_state = session.state;
                let ingest_result = {
                    let receiver = &mut session.request_receiver;
                    receiver.ingest(&mut request_bytes)
                };
                match ingest_result {
                    Ok(request) => {
                        tracing::debug!(request=?request, "Smtp Received received request");
                        let result = current_state.transition(SessionTransition::Request(request));
                        session.client = Some(src.clone());
                        session.server = Some(dst.clone());
                        session.policies = Some(self.policy_retriever.retrieve(src.ip, dst.ip));
                        session.response_receiver = ResponseReceiver::default();
                        if session.apply_transition_result(result).is_err() {
                            should_remove = true;
                        }
                    }
                    Err(smtp_proto::Error::NeedsMoreData { .. }) => {
                        session.policies = Some(self.policy_retriever.retrieve(src.ip, dst.ip));
                        session.client = Some(src);
                        session.server = Some(dst);
                        session.response_receiver = ResponseReceiver::default();
                        disposition.packet = PacketAction::QueueAndHalt;
                    }
                    Err(_) => {
                        should_remove = true;
                    }
                }
            }
        }

        self.cleanup_session(should_remove, session);
        disposition
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use smtp_proto::{MailFrom, RcptTo, Request};

    fn req(r: Request<&str>) -> SessionTransition<'_> {
        let mapped = match r {
            Request::Ehlo { host } => Request::Ehlo { host: Cow::Borrowed(host) },
            Request::Lhlo { host } => Request::Lhlo { host: Cow::Borrowed(host) },
            Request::Helo { host } => Request::Helo { host: Cow::Borrowed(host) },
            Request::Mail { from } => Request::Mail { from: MailFrom { address: Cow::Borrowed(from.address), ..Default::default() } },
            Request::Rcpt { to } => Request::Rcpt { to: RcptTo { address: Cow::Borrowed(to.address), ..Default::default() } },
            Request::Data => Request::Data,
            Request::Bdat { chunk_size, is_last } => Request::Bdat { chunk_size, is_last },
            Request::Auth { mechanism, initial_response } => Request::Auth { mechanism, initial_response: Cow::Borrowed(initial_response) },
            Request::Noop { value } => Request::Noop { value: Cow::Borrowed(value) },
            Request::Vrfy { value } => Request::Vrfy { value: Cow::Borrowed(value) },
            Request::Expn { value } => Request::Expn { value: Cow::Borrowed(value) },
            Request::Help { value } => Request::Help { value: Cow::Borrowed(value) },
            Request::Etrn { name } => Request::Etrn { name: Cow::Borrowed(name) },
            Request::Atrn { domains } => Request::Atrn { domains: domains.into_iter().map(Cow::Borrowed).collect() },
            Request::Burl { uri, is_last } => Request::Burl { uri: Cow::Borrowed(uri), is_last },
            Request::StartTls => Request::StartTls,
            Request::Rset => Request::Rset,
            Request::Quit => Request::Quit,
        };
        SessionTransition::Request(mapped)
    }

    fn resp(code: u16) -> SessionTransition<'static> {
        SessionTransition::Response(smtp_proto::Response {
            code,
            esc: [0, 0, 0],
            message: String::new(),
        })
    }

    #[test]
    fn happy_path_greeting() {
        let state = SessionState::TcpEstabilished;
        assert_eq!(state.transition(resp(220)), Ok(Some(SessionState::GreetingReceived)));
    }

    #[test]
    fn happy_path_ehlo() {
        let state = SessionState::GreetingReceived;
        assert_eq!(state.transition(req(Request::Ehlo { host: "client.example.com" })), Ok(Some(SessionState::Ready)));
    }

    #[test]
    fn happy_path_mail() {
        let state = SessionState::Ready;
        let from = MailFrom { address: "sender@example.com", ..Default::default() };
        assert_eq!(state.transition(req(Request::Mail { from })), Ok(Some(SessionState::EnvelopeOpen)));
    }

    #[test]
    fn happy_path_rcpt() {
        let state = SessionState::EnvelopeOpen;
        let to = RcptTo { address: "recipient@example.com", ..Default::default() };
        assert_eq!(state.transition(req(Request::Rcpt { to })), Ok(Some(SessionState::ReciepientSet)));
    }

    #[test]
    fn happy_path_data() {
        let state = SessionState::ReciepientSet;
        assert_eq!(state.transition(req(Request::Data)), Ok(Some(SessionState::Data(DataState::Await354))));
    }

    #[test]
    fn happy_path_data_complete() {
        let state = SessionState::Data(DataState::Complete);
        assert_eq!(state.transition(resp(250)), Ok(Some(SessionState::Ready)));
    }

    #[test]
    fn invalid_request_before_greeting() {
        let state = SessionState::TcpEstabilished;
        assert_eq!(state.transition(req(Request::Ehlo { host: "client.example.com" })), Err(()));
    }

    #[test]
    fn invalid_mail_without_ehlo() {
        let state = SessionState::GreetingReceived;
        let from = MailFrom { address: "sender@example.com", ..Default::default() };
        assert_eq!(state.transition(req(Request::Mail { from })), Err(()));
    }

    #[test]
    fn invalid_data_without_rcpt() {
        let state = SessionState::EnvelopeOpen;
        assert_eq!(state.transition(req(Request::Data)), Err(()));
    }

    #[test]
    fn invalid_rcpt_without_mail() {
        let state = SessionState::Ready;
        let to = RcptTo { address: "recipient@example.com", ..Default::default() };
        assert_eq!(state.transition(req(Request::Rcpt { to })), Err(()));
    }

    #[test]
    fn invalid_greeting_in_ready_state() {
        let state = SessionState::Ready;
        assert_eq!(state.transition(resp(220)), Err(()));
    }

    #[test]
    fn rset_from_ready() {
        let state = SessionState::Ready;
        assert_eq!(state.transition(req(Request::Rset)), Ok(Some(SessionState::Ready)));
    }

    #[test]
    fn rset_from_envelope_open() {
        let state = SessionState::EnvelopeOpen;
        assert_eq!(state.transition(req(Request::Rset)), Ok(Some(SessionState::Ready)));
    }

    #[test]
    fn rset_from_recipient_set() {
        let state = SessionState::ReciepientSet;
        assert_eq!(state.transition(req(Request::Rset)), Ok(Some(SessionState::Ready)));
    }

    #[test]
    fn rset_from_data_phase() {
        let state = SessionState::Data(DataState::Collecting);
        assert_eq!(state.transition(req(Request::Rset)), Ok(Some(SessionState::Ready)));
    }

    #[test]
    fn multiple_recipients_state() {
        let state = SessionState::ReciepientSet;
        let to = RcptTo { address: "recipient2@example.com", ..Default::default() };
        assert_eq!(state.transition(req(Request::Rcpt { to })), Ok(None));
    }

    #[test]
    fn stateless_noop() {
        let state = SessionState::Ready;
        assert_eq!(state.transition(req(Request::Noop { value: "" })), Ok(None));
    }

    #[test]
    fn stateless_vrfy() {
        let state = SessionState::Ready;
        assert_eq!(state.transition(req(Request::Vrfy { value: "user@example.com" })), Ok(None));
    }

    #[test]
    fn stateless_expn() {
        let state = SessionState::Ready;
        assert_eq!(state.transition(req(Request::Expn { value: "list@example.com" })), Ok(None));
    }

    #[test]
    fn stateless_help() {
        let state = SessionState::Ready;
        assert_eq!(state.transition(req(Request::Help { value: "MAIL" })), Ok(None));
    }

    #[test]
    fn stateless_etrn() {
        let state = SessionState::Ready;
        assert_eq!(state.transition(req(Request::Etrn { name: "example.com" })), Ok(None));
    }

    #[test]
    fn stateless_atrn() {
        let state = SessionState::Ready;
        assert_eq!(state.transition(req(Request::Atrn { domains: vec!["example.com"] })), Ok(None));
    }

    #[test]
    fn stateless_burl() {
        let state = SessionState::Ready;
        assert_eq!(state.transition(req(Request::Burl { uri: "imap://example.com/INBOX;UIDVALIDITY=1/;UID=2", is_last: false })), Ok(None));
    }

    #[test]
    fn quit_terminates_session() {
        let state = SessionState::Ready;
        assert_eq!(state.transition(req(Request::Quit)), Ok(None));
    }

    #[test]
    fn starttls_terminates_session() {
        let state = SessionState::Ready;
        assert_eq!(state.transition(req(Request::StartTls)), Err(()));
    }

    #[test]
    fn auth_in_ready_state() {
        let state = SessionState::Ready;
        assert_eq!(state.transition(req(Request::Auth { mechanism: 0, initial_response: "" })), Ok(None));
    }

    #[test]
    fn auth_in_envelope_open() {
        let state = SessionState::EnvelopeOpen;
        assert_eq!(state.transition(req(Request::Auth { mechanism: 0, initial_response: "" })), Ok(None));
    }

    #[test]
    fn helo_from_greeting_received() {
        let state = SessionState::GreetingReceived;
        assert_eq!(state.transition(req(Request::Helo { host: "client.example.com" })), Ok(Some(SessionState::Ready)));
    }

    #[test]
    fn lhlo_from_greeting_received() {
        let state = SessionState::GreetingReceived;
        assert_eq!(state.transition(req(Request::Lhlo { host: "client.example.com" })), Ok(Some(SessionState::Ready)));
    }

    #[test]
    fn ehlo_from_ready() {
        let state = SessionState::Ready;
        assert_eq!(state.transition(req(Request::Ehlo { host: "client.example.com" })), Ok(Some(SessionState::Ready)));
    }

    #[test]
    fn ehlo_from_envelope_open() {
        let state = SessionState::EnvelopeOpen;
        assert_eq!(state.transition(req(Request::Ehlo { host: "client.example.com" })), Ok(Some(SessionState::Ready)));
    }

    #[test]
    fn ehlo_from_recipient_set() {
        let state = SessionState::ReciepientSet;
        assert_eq!(state.transition(req(Request::Ehlo { host: "client.example.com" })), Ok(Some(SessionState::Ready)));
    }

    #[test]
    fn ehlo_from_data_phase_fails() {
        let state = SessionState::Data(DataState::Collecting);
        assert_eq!(state.transition(req(Request::Ehlo { host: "client.example.com" })), Err(()));
    }

    #[test]
    fn bdat_from_recipient_set() {
        let state = SessionState::ReciepientSet;
        assert_eq!(state.transition(req(Request::Bdat { chunk_size: 1024, is_last: false })), Ok(Some(SessionState::Bdat(BdatState::Collecting))));
    }

    #[test]
    fn bdat_from_wrong_state() {
        let state = SessionState::Ready;
        assert_eq!(state.transition(req(Request::Bdat { chunk_size: 1024, is_last: false })), Err(()));
    }

    #[test]
    fn non_greeting_response_no_state_change() {
        let state = SessionState::Ready;
        assert_eq!(state.transition(resp(354)), Ok(None));
    }

    #[test]
    fn response_250_in_non_data_phase() {
        let state = SessionState::Ready;
        assert_eq!(state.transition(resp(250)), Ok(None));
    }

    // ── Integration tests with real packets ──────────────────────────────────

    use std::net::{IpAddr, Ipv4Addr};
    use std::collections::HashMap;
    use etherparse::{PacketBuilder, SlicedPacket};
    use unordered_pair::UnorderedPair;
    use crate::data_plane::tcp_session_tracker::TcpIdentifier;
    use crate::zones::{DefaultPolicy, DirectionalZonePairs, ResolvedZonePair, ZonePairId};
    use crate::policy::{Policy, PolicyId};
    use uuid::Uuid;

    struct MockZoneResolver {
        zone_pair_id: ZonePairId,
    }

    impl ZoneResolver for MockZoneResolver {
        fn resolve(&self, _: &str, _: IpAddr) -> Option<ResolvedZonePair> {
            None
        }

        fn resolve_bidirectional(&self, _src_ip: IpAddr, _dst_ip: IpAddr) -> DirectionalZonePairs {
            DirectionalZonePairs {
                forward: Some(ResolvedZonePair {
                    id: self.zone_pair_id.clone(),
                    default_policy: DefaultPolicy::Drop,
                }),
                reverse: Some(ResolvedZonePair {
                    id: self.zone_pair_id.clone(),
                    default_policy: DefaultPolicy::Drop,
                }),
            }
        }
    }

    fn mock_policy_retriever() -> Arc<SmtpPolicyRetriever<MockZoneResolver>> {
        use crate::policy::provider::DiskPolicyProvider;
        use crate::rule_tree::{ArmEnd, MatchBuilder, MatchKind, Pattern, RuleTree, Verdict};
        use std::path::PathBuf;

        let zone_pair_id = ZonePairId::from(Uuid::from_u128(1001));
        let zone_resolver = Arc::new(MockZoneResolver { zone_pair_id: zone_pair_id.clone() });

        let policy_id = PolicyId::from(Uuid::from_u128(2001));
        let policy = Policy {
            name: "test-policy".into(),
            zone_pair_id,
            priority: 0,
            rule_tree: RuleTree::new(
                MatchBuilder::with_arm(
                    MatchKind::IpVer,
                    Pattern::Wildcard,
                    ArmEnd::Verdict(Verdict::Allow),
                )
                .build()
                .unwrap(),
            ),
            smtp_policy: crate::policy::SmtpPolicy::permissive(),
        };

        let mut policy_map = HashMap::new();
        policy_map.insert(policy_id, policy);

        let policy_provider = Arc::new(DiskPolicyProvider::from_policies(
            policy_map,
            PathBuf::from("/tmp"),
        ));

        Arc::new(SmtpPolicyRetriever::new(zone_resolver, policy_provider))
    }

    fn client() -> EndpointIdentifier {
        EndpointIdentifier {
            ip: IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)),
            port: crate::rule_tree::types::Port::from(54321u16),
        }
    }

    fn server() -> EndpointIdentifier {
        EndpointIdentifier {
            ip: IpAddr::V4(Ipv4Addr::new(192, 168, 1, 10)),
            port: crate::rule_tree::types::Port::from(25u16),
        }
    }

    fn session_id() -> TcpIdentifier {
        TcpIdentifier {
            endpoints: UnorderedPair::from((client(), server())),
        }
    }

    fn smtp_packet(src: &EndpointIdentifier, dst: &EndpointIdentifier, payload: &[u8]) -> Vec<u8> {
        let src_ip = match src.ip {
            IpAddr::V4(ip) => ip.octets(),
            _ => panic!("IPv6 not supported in tests"),
        };
        let dst_ip = match dst.ip {
            IpAddr::V4(ip) => ip.octets(),
            _ => panic!("IPv6 not supported in tests"),
        };

        let builder = PacketBuilder::ethernet2([0; 6], [0; 6])
            .ipv4(src_ip, dst_ip, 64)
            .tcp(u16::from(src.port), u16::from(dst.port), 1000, 8192);

        let mut packet_data = Vec::with_capacity(builder.size(payload.len()));
        builder.write(&mut packet_data, payload).unwrap();
        packet_data
    }

    fn get_session_state<ZR: ZoneResolver>(tracker: &SmtpTracker<ZR>, id: &TcpIdentifier) -> Option<SessionState> {
        tracker.sessions.get(id).map(|s| s.state)
    }

    #[test]
    fn happy_path_smtp_conversation() {
        let tracker = SmtpTracker::new(mock_policy_retriever());
        let id = session_id();

        // 1. Server greeting: 220
        let packet = smtp_packet(&server(), &client(), b"220 mail.example.com ESMTP\r\n");
        let sliced = SlicedPacket::from_ethernet(&packet).unwrap();
        tracker.on_new_packet(sliced.transport.unwrap(), &id, server(), client());
        assert_eq!(get_session_state(&tracker, &id), Some(SessionState::GreetingReceived));

        // 2. Client EHLO
        let packet = smtp_packet(&client(), &server(), b"EHLO client.example.com\r\n");
        let sliced = SlicedPacket::from_ethernet(&packet).unwrap();
        tracker.on_new_packet(sliced.transport.unwrap(), &id, client(), server());
        assert_eq!(get_session_state(&tracker, &id), Some(SessionState::Ready));

        // 3. Client MAIL FROM
        let packet = smtp_packet(&client(), &server(), b"MAIL FROM:<sender@example.com>\r\n");
        let sliced = SlicedPacket::from_ethernet(&packet).unwrap();
        tracker.on_new_packet(sliced.transport.unwrap(), &id, client(), server());
        assert_eq!(get_session_state(&tracker, &id), Some(SessionState::EnvelopeOpen));

        // 4. Client RCPT TO
        let packet = smtp_packet(&client(), &server(), b"RCPT TO:<recipient@example.com>\r\n");
        let sliced = SlicedPacket::from_ethernet(&packet).unwrap();
        tracker.on_new_packet(sliced.transport.unwrap(), &id, client(), server());
        assert_eq!(get_session_state(&tracker, &id), Some(SessionState::ReciepientSet));

        // 5. Client DATA
        let packet = smtp_packet(&client(), &server(), b"DATA\r\n");
        let sliced = SlicedPacket::from_ethernet(&packet).unwrap();
        tracker.on_new_packet(sliced.transport.unwrap(), &id, client(), server());
        assert_eq!(get_session_state(&tracker, &id), Some(SessionState::Data(DataState::Await354)));

        // 6. Server 354 Start mail input
        let packet = smtp_packet(&server(), &client(), b"354 Start mail input\r\n");
        let sliced = SlicedPacket::from_ethernet(&packet).unwrap();
        tracker.on_new_packet(sliced.transport.unwrap(), &id, server(), client());
        assert_eq!(get_session_state(&tracker, &id), Some(SessionState::Data(DataState::Collecting)));

        // 7. Client sends message body
        let packet = smtp_packet(&client(), &server(), b"Subject: Test\r\n\r\nTest message\r\n.\r\n");
        let sliced = SlicedPacket::from_ethernet(&packet).unwrap();
        tracker.on_new_packet(sliced.transport.unwrap(), &id, client(), server());
        assert_eq!(get_session_state(&tracker, &id), Some(SessionState::Data(DataState::Complete)));

        // 8. Server 250 OK (after data transmission)
        let packet = smtp_packet(&server(), &client(), b"250 OK\r\n");
        let sliced = SlicedPacket::from_ethernet(&packet).unwrap();
        tracker.on_new_packet(sliced.transport.unwrap(), &id, server(), client());
        assert_eq!(get_session_state(&tracker, &id), Some(SessionState::Ready));
    }

    #[test]
    fn first_packet_creates_session() {
        let tracker = SmtpTracker::new(mock_policy_retriever());
        let id = session_id();

        assert!(!tracker.sessions.contains_key(&id));

        let packet = smtp_packet(&server(), &client(), b"220 mail.example.com ESMTP\r\n");
        let sliced = SlicedPacket::from_ethernet(&packet).unwrap();
        tracker.on_new_packet(sliced.transport.unwrap(), &id, server(), client());

        assert!(tracker.sessions.contains_key(&id));
        assert_eq!(get_session_state(&tracker, &id), Some(SessionState::GreetingReceived));
    }

    #[test]
    fn subsequent_packets_use_existing_session() {
        let tracker = SmtpTracker::new(mock_policy_retriever());
        let id = session_id();

        let packet = smtp_packet(&server(), &client(), b"220 mail.example.com ESMTP\r\n");
        let sliced = SlicedPacket::from_ethernet(&packet).unwrap();
        tracker.on_new_packet(sliced.transport.unwrap(), &id, server(), client());

        assert_eq!(tracker.sessions.len(), 1);

        let packet = smtp_packet(&client(), &server(), b"EHLO client.example.com\r\n");
        let sliced = SlicedPacket::from_ethernet(&packet).unwrap();
        tracker.on_new_packet(sliced.transport.unwrap(), &id, client(), server());

        assert_eq!(tracker.sessions.len(), 1);
        assert_eq!(get_session_state(&tracker, &id), Some(SessionState::Ready));
    }

    #[test]
    fn different_endpoints_create_separate_sessions() {
        let tracker = SmtpTracker::new(mock_policy_retriever());

        let client1 = EndpointIdentifier {
            ip: IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)),
            port: crate::rule_tree::types::Port::from(54321u16),
        };
        let client2 = EndpointIdentifier {
            ip: IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2)),
            port: crate::rule_tree::types::Port::from(54322u16),
        };

        let id1 = TcpIdentifier {
            endpoints: UnorderedPair::from((client1.clone(), server())),
        };
        let id2 = TcpIdentifier {
            endpoints: UnorderedPair::from((client2.clone(), server())),
        };

        let packet = smtp_packet(&server(), &client1, b"220 mail.example.com ESMTP\r\n");
        let sliced = SlicedPacket::from_ethernet(&packet).unwrap();
        tracker.on_new_packet(sliced.transport.unwrap(), &id1, server(), client1.clone());

        let packet = smtp_packet(&server(), &client2, b"220 mail.example.com ESMTP\r\n");
        let sliced = SlicedPacket::from_ethernet(&packet).unwrap();
        tracker.on_new_packet(sliced.transport.unwrap(), &id2, server(), client2);

        assert_eq!(tracker.sessions.len(), 2);
        assert_eq!(get_session_state(&tracker, &id1), Some(SessionState::GreetingReceived));
        assert_eq!(get_session_state(&tracker, &id2), Some(SessionState::GreetingReceived));
    }

    #[test]
    fn session_identified_regardless_of_direction() {
        let tracker = SmtpTracker::new(mock_policy_retriever());
        let id = session_id();

        // Server → Client (greeting)
        let packet = smtp_packet(&server(), &client(), b"220 mail.example.com ESMTP\r\n");
        let sliced = SlicedPacket::from_ethernet(&packet).unwrap();
        tracker.on_new_packet(sliced.transport.unwrap(), &id, server(), client());

        // Client → Server (EHLO)
        let packet = smtp_packet(&client(), &server(), b"EHLO client.example.com\r\n");
        let sliced = SlicedPacket::from_ethernet(&packet).unwrap();
        tracker.on_new_packet(sliced.transport.unwrap(), &id, client(), server());

        assert_eq!(tracker.sessions.len(), 1);
        assert_eq!(get_session_state(&tracker, &id), Some(SessionState::Ready));
    }

    #[test]
    fn invalid_ehlo_before_greeting_removes_session() {
        let tracker = SmtpTracker::new(mock_policy_retriever());
        let id = session_id();

        let packet = smtp_packet(&client(), &server(), b"EHLO client.example.com\r\n");
        let sliced = SlicedPacket::from_ethernet(&packet).unwrap();
        tracker.on_new_packet(sliced.transport.unwrap(), &id, client(), server());

        assert!(!tracker.sessions.contains_key(&id));
    }

    #[test]
    fn invalid_mail_without_ehlo_removes_session() {
        let tracker = SmtpTracker::new(mock_policy_retriever());
        let id = session_id();

        let packet = smtp_packet(&server(), &client(), b"220 mail.example.com ESMTP\r\n");
        let sliced = SlicedPacket::from_ethernet(&packet).unwrap();
        tracker.on_new_packet(sliced.transport.unwrap(), &id, server(), client());

        let packet = smtp_packet(&client(), &server(), b"MAIL FROM:<sender@example.com>\r\n");
        let sliced = SlicedPacket::from_ethernet(&packet).unwrap();
        tracker.on_new_packet(sliced.transport.unwrap(), &id, client(), server());

        assert!(!tracker.sessions.contains_key(&id));
    }

    #[test]
    fn quit_removes_session() {
        let tracker = SmtpTracker::new(mock_policy_retriever());
        let id = session_id();

        let packet = smtp_packet(&server(), &client(), b"220 mail.example.com ESMTP\r\n");
        let sliced = SlicedPacket::from_ethernet(&packet).unwrap();
        tracker.on_new_packet(sliced.transport.unwrap(), &id, server(), client());

        let packet = smtp_packet(&client(), &server(), b"EHLO client.example.com\r\n");
        let sliced = SlicedPacket::from_ethernet(&packet).unwrap();
        tracker.on_new_packet(sliced.transport.unwrap(), &id, client(), server());

        let packet = smtp_packet(&client(), &server(), b"QUIT\r\n");
        let sliced = SlicedPacket::from_ethernet(&packet).unwrap();
        tracker.on_new_packet(sliced.transport.unwrap(), &id, client(), server());

        assert!(!tracker.sessions.contains_key(&id));
    }

    #[test]
    fn starttls_removes_session() {
        let tracker = SmtpTracker::new(mock_policy_retriever());
        let id = session_id();

        let packet = smtp_packet(&server(), &client(), b"220 mail.example.com ESMTP\r\n");
        let sliced = SlicedPacket::from_ethernet(&packet).unwrap();
        tracker.on_new_packet(sliced.transport.unwrap(), &id, server(), client());

        let packet = smtp_packet(&client(), &server(), b"EHLO client.example.com\r\n");
        let sliced = SlicedPacket::from_ethernet(&packet).unwrap();
        tracker.on_new_packet(sliced.transport.unwrap(), &id, client(), server());

        let packet = smtp_packet(&client(), &server(), b"STARTTLS\r\n");
        let sliced = SlicedPacket::from_ethernet(&packet).unwrap();
        tracker.on_new_packet(sliced.transport.unwrap(), &id, client(), server());

        assert!(!tracker.sessions.contains_key(&id));
    }

    #[test]
    fn rset_resets_to_ready() {
        let tracker = SmtpTracker::new(mock_policy_retriever());
        let id = session_id();

        let packet = smtp_packet(&server(), &client(), b"220 mail.example.com ESMTP\r\n");
        let sliced = SlicedPacket::from_ethernet(&packet).unwrap();
        tracker.on_new_packet(sliced.transport.unwrap(), &id, server(), client());

        let packet = smtp_packet(&client(), &server(), b"EHLO client.example.com\r\n");
        let sliced = SlicedPacket::from_ethernet(&packet).unwrap();
        tracker.on_new_packet(sliced.transport.unwrap(), &id, client(), server());

        let packet = smtp_packet(&client(), &server(), b"MAIL FROM:<sender@example.com>\r\n");
        let sliced = SlicedPacket::from_ethernet(&packet).unwrap();
        tracker.on_new_packet(sliced.transport.unwrap(), &id, client(), server());

        let packet = smtp_packet(&client(), &server(), b"RCPT TO:<recipient@example.com>\r\n");
        let sliced = SlicedPacket::from_ethernet(&packet).unwrap();
        tracker.on_new_packet(sliced.transport.unwrap(), &id, client(), server());

        assert_eq!(get_session_state(&tracker, &id), Some(SessionState::ReciepientSet));

        let packet = smtp_packet(&client(), &server(), b"RSET\r\n");
        let sliced = SlicedPacket::from_ethernet(&packet).unwrap();
        tracker.on_new_packet(sliced.transport.unwrap(), &id, client(), server());

        assert_eq!(get_session_state(&tracker, &id), Some(SessionState::Ready));
        assert!(tracker.sessions.contains_key(&id));
    }

    #[test]
    fn multiple_recipients() {
        let tracker = SmtpTracker::new(mock_policy_retriever());
        let id = session_id();

        let packet = smtp_packet(&server(), &client(), b"220 mail.example.com ESMTP\r\n");
        let sliced = SlicedPacket::from_ethernet(&packet).unwrap();
        tracker.on_new_packet(sliced.transport.unwrap(), &id, server(), client());

        let packet = smtp_packet(&client(), &server(), b"EHLO client.example.com\r\n");
        let sliced = SlicedPacket::from_ethernet(&packet).unwrap();
        tracker.on_new_packet(sliced.transport.unwrap(), &id, client(), server());

        let packet = smtp_packet(&client(), &server(), b"MAIL FROM:<sender@example.com>\r\n");
        let sliced = SlicedPacket::from_ethernet(&packet).unwrap();
        tracker.on_new_packet(sliced.transport.unwrap(), &id, client(), server());

        let packet = smtp_packet(&client(), &server(), b"RCPT TO:<recipient1@example.com>\r\n");
        let sliced = SlicedPacket::from_ethernet(&packet).unwrap();
        tracker.on_new_packet(sliced.transport.unwrap(), &id, client(), server());
        assert_eq!(get_session_state(&tracker, &id), Some(SessionState::ReciepientSet));

        let packet = smtp_packet(&client(), &server(), b"RCPT TO:<recipient2@example.com>\r\n");
        let sliced = SlicedPacket::from_ethernet(&packet).unwrap();
        tracker.on_new_packet(sliced.transport.unwrap(), &id, client(), server());
        assert_eq!(get_session_state(&tracker, &id), Some(SessionState::ReciepientSet));

        let packet = smtp_packet(&client(), &server(), b"RCPT TO:<recipient3@example.com>\r\n");
        let sliced = SlicedPacket::from_ethernet(&packet).unwrap();
        tracker.on_new_packet(sliced.transport.unwrap(), &id, client(), server());
        assert_eq!(get_session_state(&tracker, &id), Some(SessionState::ReciepientSet));

        let packet = smtp_packet(&client(), &server(), b"DATA\r\n");
        let sliced = SlicedPacket::from_ethernet(&packet).unwrap();
        tracker.on_new_packet(sliced.transport.unwrap(), &id, client(), server());
        assert_eq!(get_session_state(&tracker, &id), Some(SessionState::Data(DataState::Await354)));
    }

    #[test]
    fn multiple_concurrent_sessions() {
        let tracker = SmtpTracker::new(mock_policy_retriever());

        let clients: Vec<EndpointIdentifier> = (1u16..=3u16).map(|i| EndpointIdentifier {
            ip: IpAddr::V4(Ipv4Addr::new(10, 0, 0, i as u8)),
            port: crate::rule_tree::types::Port::from(50000 + i),
        }).collect();

        let ids: Vec<TcpIdentifier> = clients.iter().map(|c| TcpIdentifier {
            endpoints: UnorderedPair::from((c.clone(), server())),
        }).collect();

        for (client, id) in clients.iter().zip(&ids) {
            let packet = smtp_packet(&server(), client, b"220 mail.example.com ESMTP\r\n");
            let sliced = SlicedPacket::from_ethernet(&packet).unwrap();
            tracker.on_new_packet(sliced.transport.unwrap(), id, server(), client.clone());
        }

        assert_eq!(tracker.sessions.len(), 3);

        for (client, id) in clients.iter().zip(&ids) {
            let packet = smtp_packet(client, &server(), b"EHLO client.example.com\r\n");
            let sliced = SlicedPacket::from_ethernet(&packet).unwrap();
            tracker.on_new_packet(sliced.transport.unwrap(), id, client.clone(), server());
            assert_eq!(get_session_state(&tracker, id), Some(SessionState::Ready));
        }

        assert_eq!(tracker.sessions.len(), 3);
    }

    #[test]
    fn out_of_order_ehlo_before_greeting() {
        let tracker = SmtpTracker::new(mock_policy_retriever());
        let id = session_id();

        let packet = smtp_packet(&client(), &server(), b"EHLO client.example.com\r\n");
        let sliced = SlicedPacket::from_ethernet(&packet).unwrap();
        tracker.on_new_packet(sliced.transport.unwrap(), &id, client(), server());

        assert!(!tracker.sessions.contains_key(&id));
    }

    #[test]
    fn fragmented_smtp_command() {
        let tracker = SmtpTracker::new(mock_policy_retriever());
        let id = session_id();

        let packet = smtp_packet(&server(), &client(), b"220 mail.example.com ESMTP\r\n");
        let sliced = SlicedPacket::from_ethernet(&packet).unwrap();
        tracker.on_new_packet(sliced.transport.unwrap(), &id, server(), client());

        let packet = smtp_packet(&client(), &server(), b"EHLO cli");
        let sliced = SlicedPacket::from_ethernet(&packet).unwrap();
        tracker.on_new_packet(sliced.transport.unwrap(), &id, client(), server());

        assert_eq!(get_session_state(&tracker, &id), Some(SessionState::GreetingReceived));

        let packet = smtp_packet(&client(), &server(), b"ent.example.com\r\n");
        let sliced = SlicedPacket::from_ethernet(&packet).unwrap();
        tracker.on_new_packet(sliced.transport.unwrap(), &id, client(), server());

        assert_eq!(get_session_state(&tracker, &id), Some(SessionState::Ready));
    }

    #[test]
    fn helo_instead_of_ehlo() {
        let tracker = SmtpTracker::new(mock_policy_retriever());
        let id = session_id();

        let packet = smtp_packet(&server(), &client(), b"220 mail.example.com ESMTP\r\n");
        let sliced = SlicedPacket::from_ethernet(&packet).unwrap();
        tracker.on_new_packet(sliced.transport.unwrap(), &id, server(), client());

        let packet = smtp_packet(&client(), &server(), b"HELO client.example.com\r\n");
        let sliced = SlicedPacket::from_ethernet(&packet).unwrap();
        tracker.on_new_packet(sliced.transport.unwrap(), &id, client(), server());

        assert_eq!(get_session_state(&tracker, &id), Some(SessionState::Ready));
    }

    #[test]
    fn buffering_disposition_server_packets_pass() {
        let tracker = SmtpTracker::new(mock_policy_retriever());
        let id = session_id();

        let packet = smtp_packet(&server(), &client(), b"220 mail.example.com ESMTP\r\n");
        let sliced = SlicedPacket::from_ethernet(&packet).unwrap();
        let disposition = tracker.on_new_packet(sliced.transport.unwrap(), &id, server(), client());
        assert_eq!(disposition.packet, PacketAction::Pass);

        let packet = smtp_packet(&client(), &server(), b"EHLO client.example.com\r\n");
        let sliced = SlicedPacket::from_ethernet(&packet).unwrap();
        let disposition = tracker.on_new_packet(sliced.transport.unwrap(), &id, client(), server());
        assert_eq!(disposition.packet, PacketAction::Pass); // EHLO transitions to Ready, not buffered itself
        
        // Now in Ready state, MAIL FROM should be buffered
        let packet = smtp_packet(&client(), &server(), b"MAIL FROM:<sender@example.com>\r\n");
        let sliced = SlicedPacket::from_ethernet(&packet).unwrap();
        let disposition = tracker.on_new_packet(sliced.transport.unwrap(), &id, client(), server());
        assert_eq!(disposition.packet, PacketAction::QueueAndHalt);
    }

    #[test]
    fn buffering_disposition_client_packets_hold() {
        let tracker = SmtpTracker::new(mock_policy_retriever());
        let id = session_id();

        let packet = smtp_packet(&server(), &client(), b"220 mail.example.com ESMTP\r\n");
        let sliced = SlicedPacket::from_ethernet(&packet).unwrap();
        tracker.on_new_packet(sliced.transport.unwrap(), &id, server(), client());

        let packet = smtp_packet(&client(), &server(), b"EHLO client.example.com\r\n");
        let sliced = SlicedPacket::from_ethernet(&packet).unwrap();
        tracker.on_new_packet(sliced.transport.unwrap(), &id, client(), server());

        let packet = smtp_packet(&client(), &server(), b"MAIL FROM:<sender@example.com>\r\n");
        let sliced = SlicedPacket::from_ethernet(&packet).unwrap();
        let disposition = tracker.on_new_packet(sliced.transport.unwrap(), &id, client(), server());
        assert_eq!(disposition.packet, PacketAction::QueueAndHalt);

        let packet = smtp_packet(&client(), &server(), b"RCPT TO:<recipient@example.com>\r\n");
        let sliced = SlicedPacket::from_ethernet(&packet).unwrap();
        let disposition = tracker.on_new_packet(sliced.transport.unwrap(), &id, client(), server());
        assert_eq!(disposition.packet, PacketAction::QueueAndHalt);
    }

    #[test]
    fn buffering_disposition_data_complete() {
        let tracker = SmtpTracker::new(mock_policy_retriever());
        let id = session_id();

        let packet = smtp_packet(&server(), &client(), b"220 mail.example.com ESMTP\r\n");
        let sliced = SlicedPacket::from_ethernet(&packet).unwrap();
        tracker.on_new_packet(sliced.transport.unwrap(), &id, server(), client());

        let packet = smtp_packet(&client(), &server(), b"EHLO client.example.com\r\n");
        let sliced = SlicedPacket::from_ethernet(&packet).unwrap();
        tracker.on_new_packet(sliced.transport.unwrap(), &id, client(), server());

        let packet = smtp_packet(&client(), &server(), b"MAIL FROM:<sender@example.com>\r\n");
        let sliced = SlicedPacket::from_ethernet(&packet).unwrap();
        tracker.on_new_packet(sliced.transport.unwrap(), &id, client(), server());

        let packet = smtp_packet(&client(), &server(), b"RCPT TO:<recipient@example.com>\r\n");
        let sliced = SlicedPacket::from_ethernet(&packet).unwrap();
        tracker.on_new_packet(sliced.transport.unwrap(), &id, client(), server());

        let packet = smtp_packet(&client(), &server(), b"DATA\r\n");
        let sliced = SlicedPacket::from_ethernet(&packet).unwrap();
        let disposition = tracker.on_new_packet(sliced.transport.unwrap(), &id, client(), server());
        assert_eq!(disposition.packet, PacketAction::QueueAndHalt);

        let packet = smtp_packet(&server(), &client(), b"354 Start mail input\r\n");
        let sliced = SlicedPacket::from_ethernet(&packet).unwrap();
        tracker.on_new_packet(sliced.transport.unwrap(), &id, server(), client());

        let packet = smtp_packet(&client(), &server(), b"Subject: Test\r\n\r\nTest message\r\n.\r\n");
        let sliced = SlicedPacket::from_ethernet(&packet).unwrap();
        let disposition = tracker.on_new_packet(sliced.transport.unwrap(), &id, client(), server());
        assert_eq!(disposition.packet, PacketAction::QueueAndHalt);
        assert_eq!(disposition.unit, UnitStatus::Complete);
    }

    #[test]
    fn transaction_state_captured() {
        let tracker = SmtpTracker::new(mock_policy_retriever());
        let id = session_id();

        let packet = smtp_packet(&server(), &client(), b"220 mail.example.com ESMTP\r\n");
        let sliced = SlicedPacket::from_ethernet(&packet).unwrap();
        tracker.on_new_packet(sliced.transport.unwrap(), &id, server(), client());

        let packet = smtp_packet(&client(), &server(), b"EHLO client.example.com\r\n");
        let sliced = SlicedPacket::from_ethernet(&packet).unwrap();
        tracker.on_new_packet(sliced.transport.unwrap(), &id, client(), server());

        let packet = smtp_packet(&client(), &server(), b"MAIL FROM:<sender@example.com>\r\n");
        let sliced = SlicedPacket::from_ethernet(&packet).unwrap();
        tracker.on_new_packet(sliced.transport.unwrap(), &id, client(), server());

        if let Some(session) = tracker.sessions.get(&id) {
            assert_eq!(session.current_sender, Some("sender@example.com".to_string()));
        } else {
            panic!("Session not found");
        }

        let packet = smtp_packet(&client(), &server(), b"RCPT TO:<recipient1@example.com>\r\n");
        let sliced = SlicedPacket::from_ethernet(&packet).unwrap();
        tracker.on_new_packet(sliced.transport.unwrap(), &id, client(), server());

        let packet = smtp_packet(&client(), &server(), b"RCPT TO:<recipient2@example.com>\r\n");
        let sliced = SlicedPacket::from_ethernet(&packet).unwrap();
        tracker.on_new_packet(sliced.transport.unwrap(), &id, client(), server());

        if let Some(session) = tracker.sessions.get(&id) {
            assert_eq!(session.current_recipients.len(), 2);
            assert_eq!(session.current_recipients[0], "recipient1@example.com");
            assert_eq!(session.current_recipients[1], "recipient2@example.com");
        } else {
            panic!("Session not found");
        }
    }

    #[test]
    fn rset_clears_transaction_state() {
        let tracker = SmtpTracker::new(mock_policy_retriever());
        let id = session_id();

        let packet = smtp_packet(&server(), &client(), b"220 mail.example.com ESMTP\r\n");
        let sliced = SlicedPacket::from_ethernet(&packet).unwrap();
        tracker.on_new_packet(sliced.transport.unwrap(), &id, server(), client());

        let packet = smtp_packet(&client(), &server(), b"EHLO client.example.com\r\n");
        let sliced = SlicedPacket::from_ethernet(&packet).unwrap();
        tracker.on_new_packet(sliced.transport.unwrap(), &id, client(), server());

        let packet = smtp_packet(&client(), &server(), b"MAIL FROM:<sender@example.com>\r\n");
        let sliced = SlicedPacket::from_ethernet(&packet).unwrap();
        tracker.on_new_packet(sliced.transport.unwrap(), &id, client(), server());

        let packet = smtp_packet(&client(), &server(), b"RCPT TO:<recipient@example.com>\r\n");
        let sliced = SlicedPacket::from_ethernet(&packet).unwrap();
        tracker.on_new_packet(sliced.transport.unwrap(), &id, client(), server());

        let packet = smtp_packet(&client(), &server(), b"RSET\r\n");
        let sliced = SlicedPacket::from_ethernet(&packet).unwrap();
        tracker.on_new_packet(sliced.transport.unwrap(), &id, client(), server());

        if let Some(session) = tracker.sessions.get(&id) {
            assert_eq!(session.current_sender, None);
            assert_eq!(session.current_recipients.len(), 0);
            assert_eq!(session.current_message.len(), 0);
            assert_eq!(session.state, SessionState::Ready);
        } else {
            panic!("Session not found");
        }
    }

    #[test]
    fn bdat_multi_chunk() {
        let tracker = SmtpTracker::new(mock_policy_retriever());
        let id = session_id();

        let packet = smtp_packet(&server(), &client(), b"220 mail.example.com ESMTP\r\n");
        let sliced = SlicedPacket::from_ethernet(&packet).unwrap();
        tracker.on_new_packet(sliced.transport.unwrap(), &id, server(), client());

        let packet = smtp_packet(&client(), &server(), b"EHLO client.example.com\r\n");
        let sliced = SlicedPacket::from_ethernet(&packet).unwrap();
        tracker.on_new_packet(sliced.transport.unwrap(), &id, client(), server());

        let packet = smtp_packet(&client(), &server(), b"MAIL FROM:<sender@example.com>\r\n");
        let sliced = SlicedPacket::from_ethernet(&packet).unwrap();
        tracker.on_new_packet(sliced.transport.unwrap(), &id, client(), server());

        let packet = smtp_packet(&client(), &server(), b"RCPT TO:<recipient@example.com>\r\n");
        let sliced = SlicedPacket::from_ethernet(&packet).unwrap();
        tracker.on_new_packet(sliced.transport.unwrap(), &id, client(), server());

        let packet = smtp_packet(&client(), &server(), b"BDAT 10\r\nFirst chunk");
        let sliced = SlicedPacket::from_ethernet(&packet).unwrap();
        tracker.on_new_packet(sliced.transport.unwrap(), &id, client(), server());
        assert_eq!(get_session_state(&tracker, &id), Some(SessionState::ReciepientSet));

        let packet = smtp_packet(&client(), &server(), b"BDAT 11 LAST\r\nSecond chunk");
        let sliced = SlicedPacket::from_ethernet(&packet).unwrap();
        let disposition = tracker.on_new_packet(sliced.transport.unwrap(), &id, client(), server());
        assert_eq!(disposition.packet, PacketAction::QueueAndHalt);
        assert_eq!(disposition.unit, UnitStatus::Complete);
        assert_eq!(get_session_state(&tracker, &id), Some(SessionState::Bdat(BdatState::Complete)));
    }

    #[test]
    fn completion_packet_enqueued() {
        let tracker = SmtpTracker::new(mock_policy_retriever());
        let id = session_id();

        let packet = smtp_packet(&server(), &client(), b"220 mail.example.com ESMTP\r\n");
        let sliced = SlicedPacket::from_ethernet(&packet).unwrap();
        tracker.on_new_packet(sliced.transport.unwrap(), &id, server(), client());

        let packet = smtp_packet(&client(), &server(), b"EHLO client.example.com\r\n");
        let sliced = SlicedPacket::from_ethernet(&packet).unwrap();
        tracker.on_new_packet(sliced.transport.unwrap(), &id, client(), server());

        let packet = smtp_packet(&client(), &server(), b"MAIL FROM:<sender@example.com>\r\n");
        let sliced = SlicedPacket::from_ethernet(&packet).unwrap();
        tracker.on_new_packet(sliced.transport.unwrap(), &id, client(), server());

        let packet = smtp_packet(&client(), &server(), b"RCPT TO:<recipient@example.com>\r\n");
        let sliced = SlicedPacket::from_ethernet(&packet).unwrap();
        tracker.on_new_packet(sliced.transport.unwrap(), &id, client(), server());

        let packet = smtp_packet(&client(), &server(), b"DATA\r\n");
        let sliced = SlicedPacket::from_ethernet(&packet).unwrap();
        tracker.on_new_packet(sliced.transport.unwrap(), &id, client(), server());

        let packet = smtp_packet(&server(), &client(), b"354 Start mail input\r\n");
        let sliced = SlicedPacket::from_ethernet(&packet).unwrap();
        tracker.on_new_packet(sliced.transport.unwrap(), &id, server(), client());

        let packet = smtp_packet(&client(), &server(), b"Subject: Test\r\n\r\nBody\r\n.\r\n");
        let sliced = SlicedPacket::from_ethernet(&packet).unwrap();
        let disposition = tracker.on_new_packet(sliced.transport.unwrap(), &id, client(), server());

        assert_eq!(disposition.packet, PacketAction::QueueAndHalt, "Completion packet should be queued");
        assert_eq!(disposition.unit, UnitStatus::Complete, "Unit should be complete");
    }

    #[test]
    fn fragmented_mail_from_buffered() {
        let tracker = SmtpTracker::new(mock_policy_retriever());
        let id = session_id();

        let packet = smtp_packet(&server(), &client(), b"220 mail.example.com ESMTP\r\n");
        let sliced = SlicedPacket::from_ethernet(&packet).unwrap();
        tracker.on_new_packet(sliced.transport.unwrap(), &id, server(), client());

        let packet = smtp_packet(&client(), &server(), b"EHLO client.example.com\r\n");
        let sliced = SlicedPacket::from_ethernet(&packet).unwrap();
        tracker.on_new_packet(sliced.transport.unwrap(), &id, client(), server());

        let packet = smtp_packet(&client(), &server(), b"MAIL FR");
        let sliced = SlicedPacket::from_ethernet(&packet).unwrap();
        let disposition = tracker.on_new_packet(sliced.transport.unwrap(), &id, client(), server());
        assert_eq!(disposition.packet, PacketAction::QueueAndHalt, "Partial MAIL FROM should be buffered");

        let packet = smtp_packet(&client(), &server(), b"OM:<sender@example.com>\r\n");
        let sliced = SlicedPacket::from_ethernet(&packet).unwrap();
        let disposition = tracker.on_new_packet(sliced.transport.unwrap(), &id, client(), server());
        assert_eq!(disposition.packet, PacketAction::QueueAndHalt, "Completion of MAIL FROM should be buffered");
        assert_eq!(get_session_state(&tracker, &id), Some(SessionState::EnvelopeOpen));
    }

    #[test]
    fn lhlo_command() {
        let tracker = SmtpTracker::new(mock_policy_retriever());
        let id = session_id();

        let packet = smtp_packet(&server(), &client(), b"220 mail.example.com LMTP\r\n");
        let sliced = SlicedPacket::from_ethernet(&packet).unwrap();
        tracker.on_new_packet(sliced.transport.unwrap(), &id, server(), client());

        let packet = smtp_packet(&client(), &server(), b"LHLO client.example.com\r\n");
        let sliced = SlicedPacket::from_ethernet(&packet).unwrap();
        tracker.on_new_packet(sliced.transport.unwrap(), &id, client(), server());

        assert_eq!(get_session_state(&tracker, &id), Some(SessionState::Ready));
    }

    #[test]
    fn bdat_instead_of_data() {
        let tracker = SmtpTracker::new(mock_policy_retriever());
        let id = session_id();

        let packet = smtp_packet(&server(), &client(), b"220 mail.example.com ESMTP\r\n");
        let sliced = SlicedPacket::from_ethernet(&packet).unwrap();
        tracker.on_new_packet(sliced.transport.unwrap(), &id, server(), client());

        let packet = smtp_packet(&client(), &server(), b"EHLO client.example.com\r\n");
        let sliced = SlicedPacket::from_ethernet(&packet).unwrap();
        tracker.on_new_packet(sliced.transport.unwrap(), &id, client(), server());

        let packet = smtp_packet(&client(), &server(), b"MAIL FROM:<sender@example.com>\r\n");
        let sliced = SlicedPacket::from_ethernet(&packet).unwrap();
        tracker.on_new_packet(sliced.transport.unwrap(), &id, client(), server());

        let packet = smtp_packet(&client(), &server(), b"RCPT TO:<recipient@example.com>\r\n");
        let sliced = SlicedPacket::from_ethernet(&packet).unwrap();
        tracker.on_new_packet(sliced.transport.unwrap(), &id, client(), server());

        let packet = smtp_packet(&client(), &server(), b"BDAT 100 LAST\r\n");
        let sliced = SlicedPacket::from_ethernet(&packet).unwrap();
        tracker.on_new_packet(sliced.transport.unwrap(), &id, client(), server());

        assert_eq!(get_session_state(&tracker, &id), Some(SessionState::Bdat(BdatState::Collecting)));
    }

    #[test]
    fn noop_command() {
        let tracker = SmtpTracker::new(mock_policy_retriever());
        let id = session_id();

        let packet = smtp_packet(&server(), &client(), b"220 mail.example.com ESMTP\r\n");
        let sliced = SlicedPacket::from_ethernet(&packet).unwrap();
        tracker.on_new_packet(sliced.transport.unwrap(), &id, server(), client());

        let packet = smtp_packet(&client(), &server(), b"EHLO client.example.com\r\n");
        let sliced = SlicedPacket::from_ethernet(&packet).unwrap();
        tracker.on_new_packet(sliced.transport.unwrap(), &id, client(), server());

        let packet = smtp_packet(&client(), &server(), b"NOOP\r\n");
        let sliced = SlicedPacket::from_ethernet(&packet).unwrap();
        tracker.on_new_packet(sliced.transport.unwrap(), &id, client(), server());

        assert_eq!(get_session_state(&tracker, &id), Some(SessionState::Ready));
    }

    #[test]
    fn malformed_command_removes_session() {
        let tracker = SmtpTracker::new(mock_policy_retriever());
        let id = session_id();

        let packet = smtp_packet(&server(), &client(), b"220 mail.example.com ESMTP\r\n");
        let sliced = SlicedPacket::from_ethernet(&packet).unwrap();
        tracker.on_new_packet(sliced.transport.unwrap(), &id, server(), client());

        let packet = smtp_packet(&client(), &server(), b"EHLO client.example.com\r\n");
        let sliced = SlicedPacket::from_ethernet(&packet).unwrap();
        tracker.on_new_packet(sliced.transport.unwrap(), &id, client(), server());

        let packet = smtp_packet(&client(), &server(), b"INVALID COMMAND\r\n");
        let sliced = SlicedPacket::from_ethernet(&packet).unwrap();
        tracker.on_new_packet(sliced.transport.unwrap(), &id, client(), server());

        assert!(!tracker.sessions.contains_key(&id));
    }

    #[test]
    fn buffering_does_not_regress_state_on_replay() {
        use crate::data_plane::packet_context::PacketContext;
        use std::sync::Arc;
        
        let tracker = SmtpTracker::new(mock_policy_retriever());
        let id = session_id();
        let iface: Arc<str> = Arc::from("test0");

        // Server greeting: 220
        let packet = smtp_packet(&server(), &client(), b"220 h1.test.local ESMTP Postfix (Ubuntu)\r\n");
        let sliced = SlicedPacket::from_ethernet(&packet).unwrap();
        tracker.on_new_packet(sliced.transport.unwrap(), &id, server(), client());
        assert_eq!(get_session_state(&tracker, &id), Some(SessionState::GreetingReceived));

        // Client EHLO
        let packet = smtp_packet(&client(), &server(), b"EHLO h2\r\n");
        let sliced = SlicedPacket::from_ethernet(&packet).unwrap();
        tracker.on_new_packet(sliced.transport.unwrap(), &id, client(), server());
        assert_eq!(get_session_state(&tracker, &id), Some(SessionState::Ready));

        // Server multi-line EHLO response
        let packet = smtp_packet(&server(), &client(), b"250-h1.test.local\r\n250-PIPELINING\r\n250-SIZE 10240000\r\n250-VRFY\r\n250-ETRN\r\n250-ENHANCEDSTATUSCODES\r\n250-8BITMIME\r\n250-DSN\r\n250-SMTPUTF8\r\n250 CHUNKING\r\n");
        let sliced = SlicedPacket::from_ethernet(&packet).unwrap();
        tracker.on_new_packet(sliced.transport.unwrap(), &id, server(), client());
        assert_eq!(get_session_state(&tracker, &id), Some(SessionState::Ready));

        // MAIL FROM
        let mail_packet = smtp_packet(&client(), &server(), b"MAIL FROM:<user1@test.local>\r\n");
        let sliced = SlicedPacket::from_ethernet(&mail_packet).unwrap();
        let disp = tracker.on_new_packet(sliced.transport.unwrap(), &id, client(), server());
        assert_eq!(disp.packet, PacketAction::QueueAndHalt);
        tracker.enqueue_packet(&id, PacketContext::from_raw(mail_packet.clone(), iface.clone()).unwrap());
        assert_eq!(get_session_state(&tracker, &id), Some(SessionState::EnvelopeOpen));

        // Server 250 2.1.0 Ok
        let packet = smtp_packet(&server(), &client(), b"250 2.1.0 Ok\r\n");
        let sliced = SlicedPacket::from_ethernet(&packet).unwrap();
        tracker.on_new_packet(sliced.transport.unwrap(), &id, server(), client());
        assert_eq!(get_session_state(&tracker, &id), Some(SessionState::EnvelopeOpen));

        // RCPT TO
        let rcpt_packet = smtp_packet(&client(), &server(), b"RCPT TO:<user2@test.local>\r\n");
        let sliced = SlicedPacket::from_ethernet(&rcpt_packet).unwrap();
        let disp = tracker.on_new_packet(sliced.transport.unwrap(), &id, client(), server());
        assert_eq!(disp.packet, PacketAction::QueueAndHalt);
        tracker.enqueue_packet(&id, PacketContext::from_raw(rcpt_packet.clone(), iface.clone()).unwrap());
        assert_eq!(get_session_state(&tracker, &id), Some(SessionState::ReciepientSet));

        // Server 250 2.1.5 Ok
        let packet = smtp_packet(&server(), &client(), b"250 2.1.5 Ok\r\n");
        let sliced = SlicedPacket::from_ethernet(&packet).unwrap();
        tracker.on_new_packet(sliced.transport.unwrap(), &id, server(), client());
        assert_eq!(get_session_state(&tracker, &id), Some(SessionState::ReciepientSet));

        // DATA
        let data_packet = smtp_packet(&client(), &server(), b"DATA\r\n");
        let sliced = SlicedPacket::from_ethernet(&data_packet).unwrap();
        let disp = tracker.on_new_packet(sliced.transport.unwrap(), &id, client(), server());
        assert_eq!(disp.packet, PacketAction::QueueAndHalt);
        tracker.enqueue_packet(&id, PacketContext::from_raw(data_packet.clone(), iface.clone()).unwrap());
        assert_eq!(get_session_state(&tracker, &id), Some(SessionState::Data(DataState::Await354)));

        // Server 354
        let packet = smtp_packet(&server(), &client(), b"354 End data with <CR><LF>.<CR><LF>\r\n");
        let sliced = SlicedPacket::from_ethernet(&packet).unwrap();
        tracker.on_new_packet(sliced.transport.unwrap(), &id, server(), client());
        assert_eq!(get_session_state(&tracker, &id), Some(SessionState::Data(DataState::Collecting)));

        // Message body with headers
        let body_packet = smtp_packet(&client(), &server(), b"Date: Fri, 08 May 2026 14:29:35 +0000\r\nTo: user2@test.local\r\nFrom: user1@test.local\r\nSubject: test Fri, 08 May 2026 14:29:35 +0000\r\nMessage-Id: <20260508142935.002745@h2>\r\nX-Mailer: swaks v20240103.0 jetmore.org/john/code/swaks/\r\n\r\nTest email from h2\r\n\r\n\r\n.\r\n");
        let sliced = SlicedPacket::from_ethernet(&body_packet).unwrap();
        let disp = tracker.on_new_packet(sliced.transport.unwrap(), &id, client(), server());
        assert_eq!(disp.packet, PacketAction::QueueAndHalt);
        assert_eq!(disp.unit, UnitStatus::Complete);
        let batch = tracker.take_queued_packets(&id);
        tracker.enqueue_packet(&id, PacketContext::from_raw(body_packet.clone(), iface.clone()).unwrap());
        assert!(!batch.is_empty(), "Queued packets should be retrievable");

        assert_eq!(get_session_state(&tracker, &id), Some(SessionState::Data(DataState::Complete)));

        // Server 250 2.0.0 Ok
        let packet = smtp_packet(&server(), &client(), b"250 2.0.0 Ok: queued as D5FD480B11\r\n");
        let sliced = SlicedPacket::from_ethernet(&packet).unwrap();
        tracker.on_new_packet(sliced.transport.unwrap(), &id, server(), client());
        assert_eq!(get_session_state(&tracker, &id), Some(SessionState::Ready));

        // Simulate replaying packets through SmtpStage again (the bug)
        for pkt_ctx in batch {
            let raw = pkt_ctx.borrow_raw();
            let sliced = SlicedPacket::from_ethernet(raw).unwrap();
            tracker.on_new_packet(sliced.transport.unwrap(), &id, client(), server());
        }

        // BUG: State should NOT regress to TcpEstabilished after replay
        if let Some(session) = tracker.sessions.get(&id) {
            let final_state = session.state;
            assert!(
                !matches!(final_state, SessionState::TcpEstabilished),
                "State regressed to TcpEstabilished after replaying buffered packets. Final state: {:?}",
                final_state
            );
        } else {
            panic!("Session was removed during replay - this indicates the bug where replayed packets are treated as new connection attempts");
        }
    }
}
