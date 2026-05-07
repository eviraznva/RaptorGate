use dashmap::{DashMap, mapref::one::RefMut};
use etherparse::TransportSlice;
use smtp_proto::{request::receiver::RequestReceiver, response::parser::ResponseReceiver};
use std::borrow::Cow;

use crate::data_plane::tcp_session_tracker::{EndpointIdentifier, TcpIdentifier};

#[derive(Clone, Copy, Debug, PartialEq)]
pub(crate) enum SessionState {
    TcpEstabilished,
    GreetingReceived,
    Ready,
    EnvelopeOpen,
    ReciepientSet,
    DataPhase,
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
        assert_eq!(state.transition(req(Request::Data)), Ok(Some(SessionState::DataPhase)));
    }

    #[test]
    fn happy_path_data_complete() {
        let state = SessionState::DataPhase;
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
        let state = SessionState::DataPhase;
        assert_eq!(state.transition(req(Request::Rset)), Ok(Some(SessionState::Ready)));
    }

    #[test]
    fn multiple_recipients() {
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
        assert_eq!(state.transition(req(Request::Quit)), Err(()));
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
        let state = SessionState::DataPhase;
        assert_eq!(state.transition(req(Request::Ehlo { host: "client.example.com" })), Err(()));
    }

    #[test]
    fn bdat_from_recipient_set() {
        let state = SessionState::ReciepientSet;
        assert_eq!(state.transition(req(Request::Bdat { chunk_size: 1024, is_last: false })), Ok(Some(SessionState::DataPhase)));
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
}
