use smtp_proto::request::receiver::{BdatReceiver, DataReceiver, RequestReceiver};
use smtp_proto::response::parser::ResponseReceiver;
use std::collections::VecDeque;
use std::sync::Arc;

use crate::conntrack::tcp_identity::EndpointIdentifier;
use crate::conntrack::tuple::Direction;
use crate::data_plane::packet_context::PacketId;
use crate::dpi::smtp::{BdatState, BufferingDisposition, DataState, PacketAction, SessionState, SessionTransition, TerminatedSmtpSession, UnitStatus};
use super::smtp_policy_retriever::{SmtpPolicyRetriever, SmtpSessionPolicies};
use crate::dpi::AppProto;
use crate::l4::context::SessionContext;
use crate::l4::stage::{L4Outcome, TerminateReason};
use crate::policy::{SmtpMatch, SmtpMatchAction, SmtpPolicy};
use crate::zones::resolver::ZoneResolver;

#[derive(Clone, Copy, Debug)]
enum SmtpEvaluationPhase {
    Sender,
    Recipients,
    Message,
}

fn evaluate_sender_for_l4(session: &L4SmtpState, policies: &[SmtpPolicy]) -> bool {
    let sender = session.current_sender.as_deref().unwrap_or("");
    evaluate_policies(policies, |policy| evaluate_field(&policy.sender, sender.as_bytes()))
}

fn evaluate_recipients_for_l4(session: &L4SmtpState, policies: &[SmtpPolicy]) -> bool {
    evaluate_policies(policies, |policy| {
        session
            .current_recipients
            .iter()
            .all(|recipient| evaluate_field(&policy.recipient, recipient.as_bytes()))
    })
}

fn evaluate_message_for_l4(session: &L4SmtpState, policies: &[SmtpPolicy]) -> bool {
    evaluate_policies(policies, |policy| evaluate_field(&policy.message, &session.current_message))
}

fn evaluate_policies<F>(policies: &[SmtpPolicy], mut predicate: F) -> bool
where
    F: FnMut(&SmtpPolicy) -> bool,
{
    if policies.is_empty() {
        return false;
    }

    policies.iter().all(|policy| predicate(policy))
}

fn evaluate_field(matches: &[SmtpMatch], input: &[u8]) -> bool {
    if matches.is_empty() {
        return true;
    }

    let mut has_allow = false;
    let mut allow_matched = true;

    for matcher in matches {
        match matcher.on_match {
            SmtpMatchAction::Allow => {
                has_allow = true;
                allow_matched &= matcher.regex.is_match(input);
            }
            SmtpMatchAction::Deny => {
                if matcher.regex.is_match(input) {
                    return false;
                }
            }
        }
    }

    !has_allow || allow_matched
}

pub(crate) struct SmtpSession<ZR> {
    inner: L4SmtpState,
    buffered_ids: VecDeque<PacketId>,
    terminated: Option<TerminatedSmtpSession>,
    policy_retriever: Arc<SmtpPolicyRetriever<ZR>>,
    app_proto_set: bool,
}

impl<ZR: ZoneResolver> SmtpSession<ZR> {
    pub(crate) fn new(policy_retriever: Arc<SmtpPolicyRetriever<ZR>>) -> Self {
        Self {
            inner: L4SmtpState::default(),
            buffered_ids: VecDeque::new(),
            terminated: None,
            policy_retriever,
            app_proto_set: false,
        }
    }

    fn maybe_clear_terminated(
        &mut self,
        src: &EndpointIdentifier,
        dst: &EndpointIdentifier,
        payload: &[u8],
    ) -> bool {
        let Some(ref terminated) = self.terminated else {
            return false;
        };

        if terminated.server() != src || terminated.client() != dst {
            return true;
        }

        let mut bytes = payload.iter();
        let is_greeting = matches!(
            ResponseReceiver::default().parse(&mut bytes),
            Ok(response) if response.code == 220
        );

        if is_greeting {
            self.terminated = None;
            return false;
        }

        true
    }

    pub(crate) fn process_bytes(
        &mut self,
        ctx: &mut SessionContext,
        packet_id: PacketId,
        dir: Direction,
        payload: &[u8],
    ) -> L4Outcome {
        let (src, dst) = ctx.endpoints(dir);

        tracing::trace!(session=?ctx, "Processing SMTP bytes from session");

        if self.maybe_clear_terminated(&src, &dst, payload) {
            return L4Outcome::Terminate {
                reason: TerminateReason::SmtpPolicyDenied,
                reset: true,
            };
        }

        let (disp, remove) = self.inner.ingest_payload(
            None,
            Some(&mut self.buffered_ids),
            &self.policy_retriever,
            &mut self.terminated,
            src,
            dst,
            dir,
            payload,
        );

        if self.inner.state == SessionState::GreetingReceived && !self.app_proto_set {
            ctx.set_application_protocol(AppProto::Smtp);
            self.app_proto_set = true;
        }

        let outcome = match disp.packet {
            PacketAction::Pass => L4Outcome::Forward(vec![packet_id]),
            PacketAction::QueueAndHalt => {
                self.buffered_ids.push_back(packet_id);
                if disp.unit == UnitStatus::Complete {
                    L4Outcome::Forward(self.buffered_ids.drain(..).collect())
                } else {
                    L4Outcome::Continue
                }
            }
            PacketAction::Drop => {
                self.buffered_ids.clear();
                L4Outcome::Terminate {
                    reason: TerminateReason::SmtpPolicyDenied,
                    reset: true,
                }
            }
        };

        if remove {
            self.reset_session();
        }

        outcome
    }

    // FIXME: return l4outcome that deletes the session
    fn reset_session(&mut self) {
        self.inner = L4SmtpState::default();
        self.buffered_ids.clear();
        self.terminated = None;
        self.app_proto_set = false;
    }

    pub(crate) fn on_session_close(&mut self) {
        self.reset_session();
    }
}


pub(crate) struct L4SmtpState {
    pub state: SessionState,
    pub client: Option<EndpointIdentifier>,
    pub server: Option<EndpointIdentifier>,
    pub policies: Option<SmtpSessionPolicies>,
    pub request_receiver: RequestReceiver,
    pub response_receiver: ResponseReceiver,
    pub current_sender: Option<String>,
    pub current_recipients: Vec<String>,
    pub current_message: Vec<u8>,
    pub data_receiver: Option<DataReceiver>,
    pub bdat_receiver: Option<BdatReceiver>,
}

impl std::fmt::Debug for L4SmtpState {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("L4SmtpState")
            .field("state", &self.state)
            .field("client", &self.client)
            .field("server", &self.server)
            .field("policies", &self.policies)
            .field("request_receiver", &"RequestReceiver")
            .field("response_receiver", &"ResponseReceiver")
            .field("current_sender", &self.current_sender)
            .field("current_recipients", &self.current_recipients)
            .field("current_message", &self.current_message.len())
            .field("data_receiver", &self.data_receiver.is_some())
            .field("bdat_receiver", &self.bdat_receiver.is_some())
            .finish()
    }
}

impl Default for L4SmtpState {
    fn default() -> Self {
        Self {
            state: SessionState::TcpEstabilished,
            client: None,
            server: None,
            policies: None,
            request_receiver: RequestReceiver::default(),
            response_receiver: ResponseReceiver::default(),
            current_sender: None,
            current_recipients: Vec::new(),
            current_message: Vec::new(),
            data_receiver: None,
            bdat_receiver: None,
        }
    }
}

impl L4SmtpState {
    #[allow(clippy::too_many_lines)]
    fn ingest_payload<ZR: ZoneResolver>(
        &mut self,
        packet_queue: Option<&mut VecDeque<crate::data_plane::packet_context::PacketContext>>,
        id_queue: Option<&mut VecDeque<PacketId>>,
        policy_retriever: &Arc<SmtpPolicyRetriever<ZR>>,
        terminated: &mut Option<TerminatedSmtpSession>,
        src: EndpointIdentifier,
        dst: EndpointIdentifier,
        dir: Direction,
        payload: &[u8],
    ) -> (BufferingDisposition, bool) {
        let mut should_remove = false;
        let mut packet_queue = packet_queue;
        let mut id_queue = id_queue;
        let mut disposition = BufferingDisposition {
            packet: PacketAction::Pass,
            unit: UnitStatus::Incomplete,
        };

        if self.client.is_some() || self.server.is_some() {
            let mut evaluation_phase = None;

            match dir {
                Direction::Reply => { // reply should always be the server and original should always be the client
                    disposition.packet = PacketAction::Pass;
                    let mut bytes = payload.iter();
                    loop {
                        match self.response_receiver.parse(&mut bytes) {
                            Ok(response) => {
                                if self
                                    .apply_transition(&mut packet_queue, &mut id_queue, SessionTransition::Response(response))
                                    .is_err()
                                {
                                    should_remove = true;
                                    break;
                                }
                                if matches!(self.state, SessionState::Data(DataState::Collecting)) {
                                    self.data_receiver = Some(DataReceiver::new());
                                }
                                self.response_receiver.reset();
                            }
                            Err(smtp_proto::Error::NeedsMoreData { .. }) => break,
                            Err(_) => {
                                should_remove = true;
                                break;
                            }
                        }
                    }
                }
                Direction::Original => {
                disposition.packet = match self.state {
                    SessionState::Ready | SessionState::EnvelopeOpen | SessionState::ReciepientSet
                        | SessionState::Data(DataState::Await354 | DataState::Collecting)
                        | SessionState::Bdat(BdatState::Collecting) => PacketAction::QueueAndHalt,
                    _ => PacketAction::Pass,
                };

                let mut bytes = payload.iter();
                loop {
                    let current_state = self.state;

                    if matches!(current_state, SessionState::Data(DataState::Collecting)) {
                        if let Some(mut receiver) = self.data_receiver.take() {
                            let completed = receiver.ingest(&mut bytes, &mut self.current_message);
                            if completed {
                                self.state = SessionState::Data(DataState::Complete);
                                self.emit_l4_state_changed();
                                disposition.packet = PacketAction::QueueAndHalt;
                                disposition.unit = UnitStatus::Complete;
                                evaluation_phase = Some(SmtpEvaluationPhase::Message);
                            } else {
                                self.data_receiver = Some(receiver);
                            }
                        }
                        break;
                    }

                    if matches!(current_state, SessionState::Bdat(BdatState::Collecting)) {
                        if let Some(mut receiver) = self.bdat_receiver.take() {
                            let completed = receiver.ingest(&mut bytes, &mut self.current_message);
                            if completed {
                                let is_last = receiver.is_last;
                                if is_last {
                                    self.state = SessionState::Bdat(BdatState::Complete);
                                    disposition.packet = PacketAction::QueueAndHalt;
                                    disposition.unit = UnitStatus::Complete;
                                    evaluation_phase = Some(SmtpEvaluationPhase::Message);
                                } else {
                                    self.state = SessionState::ReciepientSet;
                                }
                            } else {
                                self.bdat_receiver = Some(receiver);
                            }
                        }
                        break;
                    }

                    match self.request_receiver.ingest(&mut bytes) {
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
                            evaluation_phase = match &request {
                                smtp_proto::Request::Mail { .. } => Some(SmtpEvaluationPhase::Sender),
                                smtp_proto::Request::Rcpt { .. } => Some(SmtpEvaluationPhase::Recipients),
                                _ => None,
                            };
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
                                self.current_sender = Some(sender_addr);
                            }

                            if let Some(rcpt_addr) = recipient {
                                self.current_recipients.push(rcpt_addr);
                            }

                            if let Some((chunk_size, is_last)) = bdat_params {
                                self.bdat_receiver = Some(BdatReceiver::new(chunk_size, is_last));
                            }

                            if self
                                .apply_transition_result(&mut packet_queue, &mut id_queue, result)
                                .is_err()
                            {
                                should_remove = true;
                                break;
                            }

                            self.request_receiver = RequestReceiver::default();

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
                                self.request_receiver = RequestReceiver::default();
                                break;
                            }
                            should_remove = true;
                            break;
                        }
                    }
                }
            }
            }

            if disposition.unit == UnitStatus::Complete && let Some(phase) = evaluation_phase {
                if let Some(ref policies) = self.policies {
                    let allowed = match phase {
                        SmtpEvaluationPhase::Sender => {
                            evaluate_sender_for_l4(self, &policies.client_to_server)
                        }
                        SmtpEvaluationPhase::Recipients => {
                            evaluate_recipients_for_l4(self, &policies.client_to_server)
                        }
                        SmtpEvaluationPhase::Message => {
                            evaluate_message_for_l4(self, &policies.client_to_server)
                        }
                    };

                    if !allowed {
                        tracing::debug!(phase = ?phase, session=?self, "Denied SMTP session");
                        if let Some(q) = packet_queue.as_mut() {
                            q.clear();
                        }
                        if let Some(ids) = id_queue.as_mut() {
                            ids.clear();
                        }
                        disposition.packet = PacketAction::Drop;

                        if let (Some(client), Some(server)) = (&self.client, &self.server) {
                            *terminated = Some(TerminatedSmtpSession::new(
                                client.clone(),
                                server.clone(),
                            ));
                        }

                        should_remove = true;
                    } else {
                        tracing::debug!(phase = ?phase, session=?self, "Allowed SMTP session");
                    }
                }
            }

            return (disposition, should_remove);
        }

        let mut response_bytes = payload.iter();
        match self.response_receiver.parse(&mut response_bytes) {
            Ok(response) => {
                tracing::debug!(response=%response, "Smtp Received received response");

                self.server = Some(src.clone());
                self.client = Some(dst.clone());
                self.policies = Some(policy_retriever.retrieve(dst.ip, src.ip));
                self.request_receiver = RequestReceiver::default();
                if self
                    .apply_transition(&mut packet_queue, &mut id_queue, SessionTransition::Response(response))
                    .is_err()
                {
                    should_remove = true;
                }
                self.response_receiver.reset();
            }
            Err(smtp_proto::Error::NeedsMoreData { .. }) => {}
            Err(_) => {
                let mut request_bytes = payload.iter();
                let current_state = self.state;
                let ingest_result = {
                    let receiver = &mut self.request_receiver;
                    receiver.ingest(&mut request_bytes)
                };
                match ingest_result {
                    Ok(request) => {
                        tracing::debug!(request=?request, "Smtp Received received request");
                        let result = current_state.transition(SessionTransition::Request(request));
                        self.client = Some(src.clone());
                        self.server = Some(dst.clone());
                        self.policies = Some(policy_retriever.retrieve(src.ip, dst.ip));
                        self.response_receiver = ResponseReceiver::default();
                        if self.apply_transition_result(&mut packet_queue, &mut id_queue, result).is_err() {
                            should_remove = true;
                        }
                    }
                    Err(smtp_proto::Error::NeedsMoreData { .. }) => {
                        self.policies = Some(policy_retriever.retrieve(src.ip, dst.ip));
                        self.client = Some(src);
                        self.server = Some(dst);
                        self.response_receiver = ResponseReceiver::default();
                        disposition.packet = PacketAction::QueueAndHalt;
                    }
                    Err(_) => {
                        should_remove = true;
                    }
                }
            }
        }

        (disposition, should_remove)
    }

    fn apply_transition(
        &mut self,
        packet_queue: &mut Option<&mut VecDeque<crate::data_plane::packet_context::PacketContext>>,
        id_queue: &mut Option<&mut VecDeque<PacketId>>,
        event: SessionTransition<'_>,
    ) -> Result<(), ()> {
        let result = self.state.transition(event);
        self.apply_transition_result(packet_queue, id_queue, result)
    }

    fn apply_transition_result(
        &mut self,
        packet_queue: &mut Option<&mut VecDeque<crate::data_plane::packet_context::PacketContext>>,
        id_queue: &mut Option<&mut VecDeque<PacketId>>,
        result: Result<Option<SessionState>, ()>,
    ) -> Result<(), ()> {
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
                        if let Some(q) = packet_queue.as_mut() {
                            q.clear();
                        }
                        if let Some(ids) = id_queue.as_mut() {
                            ids.clear();
                        }
                    }
                }
                self.state = next;
                self.emit_l4_state_changed();
                Ok(())
            }
            Ok(None) => {
                Ok(())
            }
            Err(()) => Err(()),
        }
    }

    fn emit_l4_state_changed(&self) {
        use crate::events::{emit, Event, EventKind, SmtpSessionInfo};
        
        emit(Event::new(EventKind::SmtpSessionStateChanged {
            session: SmtpSessionInfo {
                client: self.client.clone(),
                server: self.server.clone(),
            },
            new_state: format!("{:?}", self.state),
        }));

        tracing::info!(event=?Event::new(EventKind::SmtpSessionStateChanged {
            session: SmtpSessionInfo {
                client: self.client.clone(),
                server: self.server.clone(),
            },
            new_state: format!("{:?}", self.state),
        }), "Emitted SMTP session state change event");
    }
}
