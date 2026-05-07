use dashmap::{DashMap, mapref::one::RefMut};
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

enum SessionTransition<'a> {
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
                if response.code == 250 && let SessionState::DataPhase = self {
                    return Ok(Some(SessionState::Ready));
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
                        SessionState::ReciepientSet => Ok(Some(SessionState::DataPhase)),
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
                    smtp_proto::Request::Quit => Err(()),
                }
            }
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

impl SmtpTracker {
    pub fn new() -> Self {
        SmtpTracker {
            sessions: DashMap::new(),
        }
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
    ) {
        let TransportSlice::Tcp(tcp) = packet else { return };

        let mut session = self.sessions.entry(session.clone()).or_insert(SmtpSession {
            state: SessionState::TcpEstabilished,
            client: None,
            server: None,
            request_receiver: RequestReceiver::default(),
            response_receiver: ResponseReceiver::default(),
        });

        let mut should_remove = false; // need this since dashmap deadlocks when removing an entry without dropping

        let is_from_client = session.client.as_ref().is_some_and(|c| *c == src);
        let is_from_server = session.server.as_ref().is_some_and(|s| *s == src);

        if is_from_client || is_from_server {
            if is_from_server {
                let mut bytes = tcp.payload().iter();
                loop {
                    match session.response_receiver.parse(&mut bytes) {
                        Ok(response) => {
                            match session.state.transition(SessionTransition::Response(response)) {
                                Ok(Some(next)) => session.state = next,
                                Ok(None) => {}
                                Err(()) => { should_remove = true; break; }
                            }
                            session.response_receiver.reset();
                        }
                        Err(smtp_proto::Error::NeedsMoreData { .. }) => break,
                        Err(_) => { should_remove = true; break; }
                    }
                }
            } else {
                let mut bytes = tcp.payload().iter();
                loop {
                    let current_state = session.state;
                    match session.request_receiver.ingest(&mut bytes) {
                        Ok(request) => {
                            match current_state.transition(SessionTransition::Request(request)) {
                                Ok(Some(next)) => session.state = next,
                                Ok(None) => {}
                                Err(()) => { should_remove = true; break; }
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

            self.cleanup_session(should_remove, session);
            return;
        }

        let mut response_bytes = tcp.payload().iter();
        match session.response_receiver.parse(&mut response_bytes) {
            Ok(response) => {
                session.server = Some(src.clone());
                session.client = Some(dst.clone());
                session.request_receiver = RequestReceiver::default();
                match session.state.transition(SessionTransition::Response(response)) {
                    Ok(Some(next)) => session.state = next,
                    Ok(None) => {}
                    Err(()) => should_remove = true,
                }
                session.response_receiver.reset();
            }
            Err(smtp_proto::Error::NeedsMoreData { .. }) => {}
            Err(_) => {
                let mut request_bytes = tcp.payload().iter();
                let current_state = session.state;
                match session.request_receiver.ingest(&mut request_bytes) {
                    Ok(request) => {
                        let result = current_state.transition(SessionTransition::Request(request));
                        session.client = Some(src.clone());
                        session.server = Some(dst.clone());
                        session.response_receiver = ResponseReceiver::default();
                        match result {
                            Ok(Some(next)) => session.state = next,
                            Ok(None) => {}
                            Err(()) => should_remove = true,
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

        self.cleanup_session(should_remove, session);
    }
}
