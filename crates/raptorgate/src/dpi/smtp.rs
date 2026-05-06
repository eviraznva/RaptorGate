use dashmap::DashMap;
use etherparse::TransportSlice;
use smtp_proto::request::receiver::RequestReceiver;

use crate::{data_plane::tcp_session_tracker::{TcpIdentifier, TcpSession}, dpi::smtp};

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
            (SessionState::TcpEstabilished, SessionTransition::GreetingReceived) => Some(SessionState::GreetingReceived),
            (SessionState::GreetingReceived, SessionTransition::EHLOReceived) => Some(SessionState::Ready),
            (SessionState::Ready, SessionTransition::MailFromReceived) => Some(SessionState::EnvelopeOpen),
            (SessionState::EnvelopeOpen, SessionTransition::RcptToReceived) => Some(SessionState::ReciepientSet),
            (SessionState::ReciepientSet, SessionTransition::DataReceived) => Some(SessionState::DataPhase),
            (SessionState::DataPhase, SessionTransition::OkReceived) => Some(SessionState::Ready),
            _ => None,
        }
    }
}

struct SmtpSession {
    state: SessionState,
    buffer: Vec<u8>,
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

    pub fn on_new_packet(&mut self, packet: TransportSlice, session: &TcpIdentifier) {
        let mut session = self.sessions.entry(session.clone()).or_insert(SmtpSession {
            state: SessionState::TcpEstabilished,
            buffer: Vec::new(),
        });

        let request = match packet {
            TransportSlice::Tcp(tcp) => {
                // TODO: we can't assume in order tcp packets until tcp reassembly is in tcp tracker
                session.buffer.extend_from_slice(tcp.payload());
                match smtp_proto::Request::parse(&mut session.buffer.iter()) {
                    Ok(r) => { Some(r) }
                    Err(smtp_proto::Error::NeedsMoreData { .. }) => None,
                    Err(_) => {
                        session.buffer.clear();
                        self.sessions.remove(session.key());
                        None
                    }
                }
            }
            _ => None,
        };

        let Some(request) = request else { return };

        match request {
            smtp_proto::Request::Ehlo { host } => todo!(),
            smtp_proto::Request::Lhlo { host } => todo!(),
            smtp_proto::Request::Helo { host } => todo!(),
            smtp_proto::Request::Mail { from } => todo!(),
            smtp_proto::Request::Rcpt { to } => todo!(),
            smtp_proto::Request::Bdat { chunk_size, is_last } => todo!(),
            smtp_proto::Request::Auth { mechanism, initial_response } => todo!(),
            smtp_proto::Request::Noop { value } => todo!(),
            smtp_proto::Request::Vrfy { value } => todo!(),
            smtp_proto::Request::Expn { value } => todo!(),
            smtp_proto::Request::Help { value } => todo!(),
            smtp_proto::Request::Etrn { name } => todo!(),
            smtp_proto::Request::Atrn { domains } => todo!(),
            smtp_proto::Request::Burl { uri, is_last } => todo!(),
            smtp_proto::Request::StartTls => {
                tracing::warn!("TLS message encountered for SMTP, not supported, dropping session");
                self.sessions.remove(session.key());
            },
            smtp_proto::Request::Data => todo!(),
            smtp_proto::Request::Rset => todo!(),
            smtp_proto::Request::Quit => todo!(),
        }

    }
}
