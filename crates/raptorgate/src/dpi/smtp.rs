use dashmap::DashMap;
use etherparse::TransportSlice;
use smtp_proto::{request::receiver::RequestReceiver, response::parser::ResponseReceiver};
use std::borrow::Cow;

use crate::data_plane::tcp_session_tracker::{EndpointIdentifier, TcpIdentifier};

#[derive(Clone, Copy)]
enum SessionState {
    TcpEstabilished,
    GreetingReceived,
    Ready,
    EnvelopeOpen,
    ReciepientSet,
    DataPhase,
}

enum SessionTransition {
    GreetingReceived,
    EHLOReceived,
    MailFromReceived,
    RcptToReceived,
    DataReceived,
    OkReceived,
}

impl SessionState {
    fn transition(&self, event: SessionTransition) -> Option<SessionState> {
        match (self, event) {
            (SessionState::TcpEstabilished, SessionTransition::GreetingReceived) => {
                Some(SessionState::GreetingReceived)
            }
            (SessionState::GreetingReceived, SessionTransition::EHLOReceived) => {
                Some(SessionState::Ready)
            }
            (SessionState::Ready, SessionTransition::MailFromReceived) => {
                Some(SessionState::EnvelopeOpen)
            }
            (SessionState::EnvelopeOpen, SessionTransition::RcptToReceived) => {
                Some(SessionState::ReciepientSet)
            }
            (SessionState::ReciepientSet, SessionTransition::DataReceived) => {
                Some(SessionState::DataPhase)
            }
            (SessionState::DataPhase, SessionTransition::OkReceived) => Some(SessionState::Ready),
            _ => None,
        }
    }
}

struct SmtpSession {
    state: SessionState,
    client: Option<EndpointIdentifier>,
    server: Option<EndpointIdentifier>,
    request_receiver: RequestReceiver,
    response_receiver: ResponseReceiver,
}

struct SmtpTracker {
    sessions: DashMap<TcpIdentifier, SmtpSession>,
}

fn handle_response(state: &SessionState, response: smtp_proto::Response<String>) -> Option<SessionState> {
    if response.code == 220 {
        state.transition(SessionTransition::GreetingReceived)
    } else {
        Some(state.clone())
    }
}

fn handle_request(state: &SessionState, request: &smtp_proto::Request<Cow<str>>) -> Option<SessionState> {
    if matches!(state, SessionState::TcpEstabilished) {
        return None;
    }

    match request {
        smtp_proto::Request::Ehlo { .. }
        | smtp_proto::Request::Lhlo { .. }
        | smtp_proto::Request::Helo { .. } => match state {
            SessionState::GreetingReceived
            | SessionState::Ready
            | SessionState::EnvelopeOpen
            | SessionState::ReciepientSet => Some(SessionState::Ready),
            _ => None,
        },
        smtp_proto::Request::Mail { .. } => state.transition(SessionTransition::MailFromReceived),
        smtp_proto::Request::Rcpt { .. } => match state {
            SessionState::EnvelopeOpen => Some(SessionState::ReciepientSet),
            SessionState::ReciepientSet => Some(state.clone()),
            _ => None,
        },
        smtp_proto::Request::Data | smtp_proto::Request::Bdat { .. } => {
            state.transition(SessionTransition::DataReceived)
        }
        smtp_proto::Request::Auth { .. } => {
            tracing::info!("SMTP AUTH encountered; not yet supported");
            if matches!(state, SessionState::DataPhase) {
                Some(state.clone())
            } else {
                Some(state.clone())
            }
        }
        smtp_proto::Request::Noop { .. }
        | smtp_proto::Request::Vrfy { .. }
        | smtp_proto::Request::Expn { .. }
        | smtp_proto::Request::Help { .. }
        | smtp_proto::Request::Etrn { .. }
        | smtp_proto::Request::Atrn { .. }
        | smtp_proto::Request::Burl { .. } => {
            if matches!(state, SessionState::DataPhase) {
                Some(state.clone())
            } else {
                Some(state.clone())
            }
        }
        smtp_proto::Request::StartTls => {
            tracing::warn!("TLS message encountered for SMTP, not supported, dropping session");
            None
        }
        smtp_proto::Request::Rset => Some(SessionState::Ready),
        smtp_proto::Request::Quit => None,
    }
}

impl SmtpTracker {
    pub fn new() -> Self {
        SmtpTracker {
            sessions: DashMap::new(),
        }
    }

    pub fn on_new_packet(
        &mut self,
        packet: TransportSlice,
        session: &TcpIdentifier,
        src: EndpointIdentifier,
        dst: EndpointIdentifier,
    ) {
        let TransportSlice::Tcp(tcp) = packet else { return };

        let mut session = self.sessions.entry(session.clone()).or_insert(SmtpSession {
            state: SessionState::TcpEstabilished,
            client: None,
            server: None,
            request_receiver: RequestReceiver::default(),
            response_receiver: ResponseReceiver::default(),
        });

        let mut should_remove = false;

        let is_from_client = session.client.as_ref().is_some_and(|c| *c == src);
        let is_from_server = session.server.as_ref().is_some_and(|s| *s == src);

        if is_from_client || is_from_server {
            if is_from_server {
                let mut bytes = tcp.payload().iter();
                loop {
                    match session.response_receiver.parse(&mut bytes) {
                        Ok(response) => {
                            if let Some(next_state) = handle_response(&session.state, response) {
                                session.state = next_state;
                            } else {
                                should_remove = true;
                                break;
                            }
                            session.response_receiver.reset();
                        }
                        Err(smtp_proto::Error::NeedsMoreData { .. }) => break,
                        Err(_) => {
                            should_remove = true;
                            break;
                        }
                    }
                }
            } else {
                let mut bytes = tcp.payload().iter();
                loop {
                    let current_state = session.state;
                    match session.request_receiver.ingest(&mut bytes) {
                        Ok(request) => {
                            if let Some(next_state) = handle_request(&current_state, &request) {
                                session.state = next_state;
                            } else {
                                should_remove = true;
                                break;
                            }
                        }
                        Err(smtp_proto::Error::NeedsMoreData { .. }) => break,
                        Err(_) => {
                            if matches!(current_state, SessionState::DataPhase) {
                                session.request_receiver = RequestReceiver::default();
                                break;
                            }
                            should_remove = true;
                            break;
                        }
                    }
                }
            }

            if should_remove {
                let key = session.key().clone();
                drop(session);
                self.sessions.remove(&key);
            }
            return;
        }

        let mut response_bytes = tcp.payload().iter();
        match session.response_receiver.parse(&mut response_bytes) {
            Ok(response) => {
                session.server = Some(src.clone());
                session.client = Some(dst.clone());
                session.request_receiver = RequestReceiver::default();
                if let Some(next_state) = handle_response(&session.state, response) {
                    session.state = next_state;
                } else {
                    should_remove = true;
                }
                session.response_receiver.reset();
            }
            Err(smtp_proto::Error::NeedsMoreData { .. }) => {
                let mut request_bytes = tcp.payload().iter();
                let current_state = session.state;
                match session.request_receiver.ingest(&mut request_bytes) {
                    Ok(request) => {
                        let next_state = handle_request(&current_state, &request);
                        session.client = Some(src.clone());
                        session.server = Some(dst.clone());
                        session.response_receiver = ResponseReceiver::default();
                        if let Some(next_state) = next_state {
                            session.state = next_state;
                        } else {
                            should_remove = true;
                        }
                    }
                    Err(smtp_proto::Error::NeedsMoreData { .. }) => {}
                    Err(_) => {
                        session.request_receiver = RequestReceiver::default();
                    }
                }
            }
            Err(_) => {
                let mut request_bytes = tcp.payload().iter();
                let current_state = session.state;
                match session.request_receiver.ingest(&mut request_bytes) {
                    Ok(request) => {
                        let next_state = handle_request(&current_state, &request);
                        session.client = Some(src.clone());
                        session.server = Some(dst.clone());
                        session.response_receiver = ResponseReceiver::default();
                        if let Some(next_state) = next_state {
                            session.state = next_state;
                        } else {
                            should_remove = true;
                        }
                    }
                    Err(smtp_proto::Error::NeedsMoreData { .. }) => {
                        session.client = Some(src);
                        session.server = Some(dst);
                        session.response_receiver = ResponseReceiver::default();
                    }
                    Err(_) => {
                        should_remove = true;
                    }
                }
            }
        }

        if should_remove {
            let key = session.key().clone();
            drop(session);
            self.sessions.remove(&key);
        }
    }
}
