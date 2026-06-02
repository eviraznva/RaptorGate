use std::sync::Arc;
use bitflags::bitflags;
use std::time::{Duration, Instant};
use etherparse::{SlicedPacket, TcpSlice, TransportSlice};

use crate::conntrack::entry::ConntrackEntry;
use crate::conntrack::config::ConntrackConfig;
use crate::conntrack::tuple::{Direction, Protocol};
use crate::conntrack::observer::{AnomalyKind, CtObserver, ObserverRegistry};
use crate::conntrack::proto::{CtVerdict, NewStateError, NewStateOutcome, ProtoState, ProtocolHandler};
use crate::conntrack::reassembler;
use crate::data_plane::packet_context::PacketId;

#[derive(Debug, Clone, Default)]
pub struct TcpProtoState {
    pub state: TcpConntrack,
    pub last_dir: Option<Direction>,
    pub retrans: u8,
    pub last_index: TcpFlagBit,
    pub seen: [TcpDirState; 2],  // [Original, Reply]
}

pub const TD_FLAG_WSCALE: u8     = 1 << 0; // Negocjowano window scale option w handshake'u
pub const TD_FLAG_SACK_PERM: u8  = 1 << 1; // Negocjowano SACK Permitted option w handshake'u
pub const TD_FLAG_BE_LIBERAL: u8 = 1 << 2;

#[derive(Debug, Clone, Default)]
pub struct TcpDirState {
    pub td_end: u32,        // Sequence number ostatniego bajtu wysłanego
    pub td_maxend: u32,     // Max sekwencja jaką wolno przyjąć (end + window)
    pub td_maxwin: u32,     // Największe okienko widziane
    pub td_scale: u8,       // Window scale option
    pub flags: u8,          // Bity per direction (SACK_PERM, WINDOW_SCALE, BE_LIBERAL)

    pub last_seq: u32,      // Sequence number ostatniego pakietu z tej strony
    pub last_ack: u32,      // Acknowledgment number ostatniego pakietu z tej strony
    pub last_end: u32,      // Ostatni bajt (seq + payload + SYN/FIN) z tej strony
    pub last_win: u32,      // Window size ostatniego pakietu z tej strony (po uwzględnieniu scale)
    pub last_wscale: u8,    // Window scale ostatniego pakietu z tej strony (jeśli był SYN)
    pub last_flags: u16,    // Ostatnie flagi TCP z tej strony
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(u8)]
pub enum TcpConntrack {
    None        = 0,   // Świeży entry, jeszcze nie sklasyfikowany
    SynSent     = 1,   // SYN-only (klient → serwer)
    SynRecv     = 2,   // SYN-ACK (serwer → klient)
    Established = 3,   // ACK po SYN-ACK — handshake done
    FinWait     = 4,   // FIN widziany (jedna strona zamknęła)
    CloseWait   = 5,   // ACK po FIN
    LastAck     = 6,   // FIN w drugą stronę
    TimeWait    = 7,   // ACK po LastAck — flow domknięty
    Close       = 8,   // RST — flow zerwany
    SynSent2    = 9,   // simultaneous open: SYN z reply direction zanim widziano SYN-ACK
}

impl Default for TcpConntrack {
    fn default() -> Self { TcpConntrack::None }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
#[repr(usize)]
pub enum TcpFlagBit {
    Syn    = 0,  // SYN bez ACK
    SynAck = 1,  // SYN + ACK
    Fin    = 2,  // FIN (z lub bez ACK)
    Ack    = 3,  // ACK (bez SYN/FIN/RST)
    Rst    = 4,  // RST
    #[default]
    None   = 5,  // brak żadnej znaczącej flagi
}

bitflags! {
    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    pub struct TcpFlags: u16 {
      const FIN = 1 << 0;
      const SYN = 1 << 1;
      const RST = 1 << 2;
      const PSH = 1 << 3;
      const ACK = 1 << 4;
      const URG = 1 << 5;
      const ECE = 1 << 6;
      const CWR = 1 << 7;
      const NS  = 1 << 8;
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Transition {
    To(TcpConntrack),  // Przejdź do nowego stanu
    Invalid,           // Pakiet zły
    Ignore,            // Ignoruj ale nie zmieniaj stanu
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum WindowVerdict {
    InWindow,
    OutOfWindow,
    LiberalAccept,  // Out-of-window ale be_liberal pozwala
}

fn classify_flags(flags: TcpFlags) -> TcpFlagBit {
    if flags.contains(TcpFlags::RST) {
        TcpFlagBit::Rst
    } else if flags.contains(TcpFlags::FIN) {
        TcpFlagBit::Fin
    } else if flags.contains(TcpFlags::SYN) {
        if flags.contains(TcpFlags::ACK) {
            TcpFlagBit::SynAck
        } else {
            TcpFlagBit::Syn
        }
    } else if flags.contains(TcpFlags::ACK) {
        TcpFlagBit::Ack
    } else {
        TcpFlagBit::None
    }
}

const MAXACKWINDOW: u32 = 66_000;  // ≈ największy możliwy window bez scale

const TRANSITIONS: [[[Transition; 10]; 6]; 2] = {
    use Transition::{Ignore as IG, Invalid as IV, To};
    use TcpConntrack::*;

    [
        // ORIGINAL, kierunek (klient → serwer)
        [
            // SYN
            [To(SynSent), To(SynSent), IG, IG, IG, IG, IG, To(SynSent), To(SynSent), To(SynSent2)],
            // SYNACK (klient nie powinien wysyłać SYN-ACK, sam INVALID)
            [IV, IV, To(SynRecv), IV, IV, IV, IV, IV, IV, To(SynRecv)],
            // FIN
            [IV, IV, To(FinWait), To(FinWait), To(LastAck), To(LastAck), To(LastAck), To(TimeWait), To(Close), IV],
            // ACK
            [To(Established), IV, To(Established), To(Established), To(CloseWait), To(CloseWait), To(TimeWait), To(TimeWait), To(Close), IV],
            // RST (RST z byle którego stanu zamyka flow)
            [IV, To(Close), To(Close), To(Close), To(Close), To(Close), To(Close), To(Close), To(Close), To(Close)],
            // None (pakiet bez znaczącej flagi)
            [IV, IV, IV, IV, IV, IV, IV, IV, IV, IV],
        ],
        // REPLY direction (serwer → klient)
        [
            // SYN (serwer wysyła SYN: simultaneous open)
            [IV, To(SynSent2), IV, IV, IV, IV, IV, To(SynSent), IV, To(SynSent2)],
            // SYNACK (typowa odpowiedź serwera na SYN klienta)
            [IV, To(SynRecv), IG, IG, IG, IG, IG, IG, IG, To(SynRecv)],
            // FIN
            [IV, IV, To(FinWait), To(FinWait), To(LastAck), To(LastAck), To(LastAck), To(TimeWait), To(Close), IV],
            // ACK
            [IV, IG, To(SynRecv), To(Established), To(CloseWait), To(CloseWait), To(TimeWait), To(TimeWait), To(Close), IG],
            // RST
            [IV, To(Close), To(Close), To(Close), To(Close), To(Close), To(Close), To(Close), To(Close), To(Close)],
            // None
            [IV, IV, IV, IV, IV, IV, IV, IV, IV, IV],
        ],
    ]
};

fn next_state(dir: Direction, flag: TcpFlagBit, current: TcpConntrack) -> Transition {
    let dir_idx = match dir {
        Direction::Original => 0,
        Direction::Reply => 1,
    };

    TRANSITIONS[dir_idx][flag as usize][current as usize]
}

pub struct TcpHandler {
    observers: Arc<ObserverRegistry>,
}

impl TcpHandler {
    pub fn new(observers: Arc<ObserverRegistry>) -> Self {
        Self { observers }
    }
}

impl ProtocolHandler for TcpHandler {
    fn proto(&self) -> Protocol {
        Protocol::Tcp
    }

    fn new_state(&self, pkt: &SlicedPacket, _dir: Direction, config: &ConntrackConfig) -> Result<NewStateOutcome, NewStateError> {
        let tcp = extract_tcp(pkt)?;
        let flags = parse_flags(&tcp);
        let flag_bit = classify_flags(flags);

        if flag_bit != TcpFlagBit::Syn && !config.tcp.loose {
            return Err(NewStateError::InvalidFirst {
                proto: Protocol::Tcp,
                reason: "first packet not SYN and tcp.loose disabled",
            });
        }

        let initial_state = match flag_bit {
            TcpFlagBit::Syn => TcpConntrack::SynSent,
            TcpFlagBit::Ack | TcpFlagBit::SynAck if config.tcp.loose => TcpConntrack::Established,

            _ => return Err(NewStateError::InvalidFirst {
                proto: Protocol::Tcp,
                reason: "first packet has unsupported flags",
            }),
        };

        let mut seen_orig = TcpDirState::default();

        let payload_len = tcp.payload().len() as u32;

        let seq = tcp.sequence_number();
        let ack = tcp.acknowledgment_number();
        let win = u32::from(tcp.window_size());

        let syn_fin_addon = u32::from(flags.contains(TcpFlags::SYN)) + u32::from(flags.contains(TcpFlags::FIN));

        seen_orig.td_end = seq.wrapping_add(payload_len).wrapping_add(syn_fin_addon);
        seen_orig.td_maxwin = win.max(1);
        seen_orig.td_maxend = seen_orig.td_end.wrapping_add(seen_orig.td_maxwin);

        // Parsuj opcje SYN
        if flags.contains(TcpFlags::SYN) {
            let opts = parse_options(&tcp);

            if let Some(ws) = opts.window_scale {
                seen_orig.td_scale = ws;
                seen_orig.flags |= TD_FLAG_WSCALE;
            }

            if opts.sack_permitted {
                seen_orig.flags |= TD_FLAG_SACK_PERM;
            }
        }

        seen_orig.last_seq = seq;
        seen_orig.last_ack = ack;
        seen_orig.last_end = seen_orig.td_end;
        seen_orig.last_win = win;
        seen_orig.last_wscale = seen_orig.td_scale;
        seen_orig.last_flags = flags.bits();

        let state = TcpProtoState {
            state: initial_state,
            last_dir: Some(Direction::Original),
            retrans: 0,
            last_index: flag_bit,
            seen: [seen_orig, TcpDirState::default()],
        };

        Ok(NewStateOutcome::State(ProtoState::Tcp(state)))
    }

    fn update(
        &self,
        entry: &ConntrackEntry,
        pkt: &SlicedPacket,
        dir: Direction,
        _now: Instant,
        config: &ConntrackConfig,
        packet_id: PacketId,
    ) -> CtVerdict {
        let Ok(tcp) = extract_tcp(pkt) else {
            return CtVerdict::Invalid;
        };

        let flags = parse_flags(&tcp);
        let flag_bit = classify_flags(flags);

        let mut guard = entry.proto_state.lock();

        let ProtoState::Tcp(state) = &mut *guard else {
            return CtVerdict::Invalid;
        };

        let transition = next_state(dir, flag_bit, state.state);

        let new_state = match transition {
            Transition::To(s) => s,

            Transition::Ignore => {
                sync_last_on_ignore(state, &tcp, flags, dir);
                return CtVerdict::Accept;
            },

            Transition::Invalid => {
                if config.tcp.be_liberal { return CtVerdict::Accept; }
                return CtVerdict::Invalid;
            }
        };

        // RST validation — wykonaj PRZED tcp_in_window.
        if flag_bit == TcpFlagBit::Rst {
            let r_end = state.seen[opposite_dir(dir) as usize].td_end;

            if tcp.sequence_number() != r_end {
                if config.tcp.ignore_invalid_rst {
                    return CtVerdict::Accept;
                }

                return CtVerdict::Invalid;
            }
        }

        // Snapshot last_* PRZED tcp_in_window (które je nadpisuje).
        let last_snapshot = state.seen[dir as usize].clone();

        let window_verdict = tcp_in_window(state, &tcp, flags, dir, config);

        match window_verdict {
            WindowVerdict::InWindow => {
                let payload_data = tcp.payload();
                let dir_idx = dir as usize;
                
                let mut chunks = if !payload_data.is_empty() {
                    let mut reass = entry.reassembly.lock();
                    
                    let c = reassembler::feed(
                        &mut reass.dirs[dir_idx],
                        &config.reassembly,
                        tcp.sequence_number(),
                        packet_id,
                        payload_data,
                    );
                    
                    drop(reass);
                    
                    c
                } else {
                    Vec::new()
                };
                
                if matches!(flag_bit, TcpFlagBit::Fin | TcpFlagBit::Rst) {
                    let mut reass = entry.reassembly.lock();
                    
                    chunks.extend(reassembler::flush(&mut reass.dirs[dir_idx]));
                    
                    drop(reass);
                }
                
                for chunk in chunks {
                    self.observers.fire_payload(entry, dir, &chunk);
                }
            },

            WindowVerdict::LiberalAccept => {
                self.observers.fire_anomaly(entry, AnomalyKind::TcpOutOfWindow);
            },
            WindowVerdict::OutOfWindow => return CtVerdict::Invalid,
        }

        // Retrans po porównaniu z last_* z snapshotu.
        let seq = tcp.sequence_number();
        let ack = tcp.acknowledgment_number();

        let win_raw = u32::from(tcp.window_size());
        let payload = tcp.payload().len() as u32;

        let syn_fin = u32::from(flags.contains(TcpFlags::SYN)) + u32::from(flags.contains(TcpFlags::FIN));

        let end = seq.wrapping_add(payload).wrapping_add(syn_fin);

        let same_packet = last_snapshot.last_seq == seq
            && last_snapshot.last_ack == ack
            && last_snapshot.last_end == end
            && last_snapshot.last_win == win_raw
            && last_snapshot.last_flags == flags.bits();

        if same_packet {
            state.retrans = state.retrans.saturating_add(1);
        } else {
            state.retrans = 0;
        }

        state.state = new_state;
        state.last_dir = Some(dir);
        state.last_index = flag_bit;

        CtVerdict::Accept
    }

    fn timeout(&self, state: &ProtoState, config: &ConntrackConfig) -> Duration {
        let ProtoState::Tcp(tcp) = state else {
            return config.tcp.timeout.established;
        };

        match tcp.state {
            TcpConntrack::None => config.generic_timeout,
            TcpConntrack::SynSent | TcpConntrack::SynSent2  => config.tcp.timeout.syn_sent,
            TcpConntrack::SynRecv => config.tcp.timeout.syn_recv,

            TcpConntrack::Established => {
                if tcp.retrans > config.tcp.max_retrans {
                    config.tcp.timeout.max_retrans
                } else {
                    config.tcp.timeout.established
                }
            }

            TcpConntrack::FinWait => config.tcp.timeout.fin_wait,
            TcpConntrack::CloseWait => config.tcp.timeout.close_wait,
            TcpConntrack::LastAck => config.tcp.timeout.last_ack,
            TcpConntrack::TimeWait => config.tcp.timeout.time_wait,
            TcpConntrack::Close => config.tcp.timeout.close,
        }
    }

    fn is_assured(&self, state: &ProtoState) -> bool {
        let ProtoState::Tcp(tcp) = state else { return false; };

        matches!(
          tcp.state,
          TcpConntrack::Established | TcpConntrack::FinWait | TcpConntrack::CloseWait | TcpConntrack::LastAck | TcpConntrack::TimeWait
      )
    }

    fn register_observer(&self, observer: Arc<dyn CtObserver>) {
        self.observers.register(observer);
    }
}

/// Parsuje opcje TCP wyciągając informacje istotne dla window check.
struct TcpOptionsInfo {
    pub window_scale: Option<u8>,
    pub sack_permitted: bool,
    pub sack_blocks: Vec<(u32, u32)>,
}

fn parse_options(tcp: &TcpSlice) -> TcpOptionsInfo {
    let mut info = TcpOptionsInfo {
        window_scale: None,
        sack_permitted: false,
        sack_blocks: Vec::new(),
    };

    let opts = tcp.options();

    let mut i = 0usize;

    while i < opts.len() {
        let kind = opts[i];

        match kind {
            0 => break,
            1 => i += 1,

            2 => {
                if i + 4 <= opts.len() { i += 4 } else { break; }
            }

            3 => {
                if i + 3 <= opts.len() {
                    info.window_scale = Some(opts[i + 2].min(14));
                    i += 3;
                } else { break; }
            }

            4 => {
                info.sack_permitted = true;
                i += 2;
            }

            5 => {
                if i + 2 > opts.len() { break; }

                let len = opts[i + 1] as usize;

                if len < 2 || i + len > opts.len() || (len - 2) % 8 != 0 { break; }

                let mut j = i + 2;

                while j + 8 <= i + len {
                    let l = u32::from_be_bytes([opts[j], opts[j+1], opts[j+2], opts[j+3]]);
                    let r = u32::from_be_bytes([opts[j+4], opts[j+5], opts[j+6], opts[j+7]]);

                    info.sack_blocks.push((l, r));

                    j += 8;
                }

                i += len;
            }

            _ => {
                if i + 1 < opts.len() {
                    let len = opts[i + 1] as usize;

                    if len < 2 || i + len > opts.len() { break; }

                    i += len;
                } else { break; }
            }
        }
    }

    info
}

fn extract_tcp<'a>(pkt: &'a SlicedPacket) -> Result<TcpSlice<'a>, NewStateError> {
    match pkt.transport.as_ref() {
        Some(TransportSlice::Tcp(tcp)) => Ok(tcp.clone()),

        Some(_) => Err(NewStateError::InvalidFirst {
            proto: Protocol::Tcp,
            reason: "transport is not TCP",
        }),

        None => Err(NewStateError::MissingTransport),
    }
}

fn parse_flags(tcp: &TcpSlice) -> TcpFlags {
    let mut f = TcpFlags::empty();

    if tcp.fin() { f |= TcpFlags::FIN; }
    if tcp.syn() { f |= TcpFlags::SYN; }
    if tcp.rst() { f |= TcpFlags::RST; }
    if tcp.psh() { f |= TcpFlags::PSH; }
    if tcp.ack() { f |= TcpFlags::ACK; }
    if tcp.urg() { f |= TcpFlags::URG; }
    if tcp.ece() { f |= TcpFlags::ECE; }
    if tcp.cwr() { f |= TcpFlags::CWR; }

    f
}

#[inline] pub fn seq_after_eq(a: u32, b: u32) -> bool { a.wrapping_sub(b) < (1u32 << 31) }

#[inline] pub fn seq_after(a: u32, b: u32) -> bool {
    let d = a.wrapping_sub(b);

    d != 0 && d < (1u32 << 31)
}

#[inline] fn seq_before_eq(a: u32, b: u32) -> bool {
    seq_after_eq(b, a)
}

fn tcp_in_window(state: &mut TcpProtoState, tcp: &TcpSlice, flags: TcpFlags, dir: Direction, config: &ConntrackConfig) -> WindowVerdict {
    let sender_idx = dir as usize;
    let receiver_idx = opposite_dir(dir) as usize;

    let seq = tcp.sequence_number();
    let ack = tcp.acknowledgment_number();

    let win_raw = u32::from(tcp.window_size());
    let payload = tcp.payload().len() as u32;

    let syn_fin = u32::from(flags.contains(TcpFlags::SYN)) + u32::from(flags.contains(TcpFlags::FIN));
    let end = seq.wrapping_add(payload).wrapping_add(syn_fin);

    // Parsuj WS/SACK_PERM PRZED użyciem skali (tylko na SYN/SYN-ACK)
    if flags.contains(TcpFlags::SYN) {
        let opts = parse_options(tcp);

        if let Some(ws) = opts.window_scale {
            state.seen[sender_idx].td_scale = ws;
            state.seen[sender_idx].flags |= TD_FLAG_WSCALE;
        }

        if opts.sack_permitted {
            state.seen[sender_idx].flags |= TD_FLAG_SACK_PERM;
        }
    }

    // Skala efektywna: tylko gdy obie strony wynegocjowały WS
    let scale = if (state.seen[sender_idx].flags & TD_FLAG_WSCALE) != 0 && (state.seen[receiver_idx].flags & TD_FLAG_WSCALE) != 0 {
        state.seen[sender_idx].td_scale
    } else { 0 };

    if (state.seen[sender_idx].flags & TD_FLAG_SACK_PERM) != 0 && (state.seen[receiver_idx].flags & TD_FLAG_SACK_PERM) != 0 && flags.contains(TcpFlags::ACK) {
        let opts = parse_options(tcp);

        tcp_sack(&mut state.seen[receiver_idx], &opts.sack_blocks);
    }

    let win = win_raw << scale;

    // Pierwszy pakiet od tego sendera
    if state.seen[sender_idx].td_maxwin == 0 {
        state.seen[sender_idx].td_end = end;
        state.seen[sender_idx].td_maxwin = win.max(1);
        state.seen[sender_idx].td_maxend = end.wrapping_add(win.max(1));

        record_last(&mut state.seen[sender_idx], seq, ack, end, win_raw, scale, flags);

        return WindowVerdict::InWindow;
    }

    let sender = &state.seen[sender_idx];
    let receiver = &state.seen[receiver_idx];

    let cond1 = seq_after_eq(end, sender.td_end.wrapping_sub(receiver.td_maxwin.max(1)));

    let cond2 = seq_before_eq(seq, sender.td_maxend.wrapping_add(1));

    let cond3 = if flags.contains(TcpFlags::ACK) {
        seq_before_eq(ack, receiver.td_end)
    } else { true };

    let cond4 = if flags.contains(TcpFlags::ACK) {
        seq_after_eq(ack, receiver.td_end.wrapping_sub(MAXACKWINDOW))
    } else { true };

    let in_window = cond1 && cond2 && cond3 && cond4;

    if in_window {
        update_sender_after_accept(&mut state.seen[sender_idx], end, ack, win);

        record_last(&mut state.seen[sender_idx], seq, ack, end, win_raw, scale, flags);

        WindowVerdict::InWindow
    } else if config.tcp.be_liberal {
        update_sender_after_accept(&mut state.seen[sender_idx], end, ack, win);

        record_last(&mut state.seen[sender_idx], seq, ack, end, win_raw, scale, flags);

        WindowVerdict::LiberalAccept
    } else {
        WindowVerdict::OutOfWindow
    }
}

fn tcp_sack(receiver: &mut TcpDirState, blocks: &[(u32, u32)]) {
    for &(_, r) in blocks {
        if seq_after(r, receiver.td_end) {
            receiver.td_end = r;
        }
    }
}

/// Wrapper na `update_sender_after_accept` używający surowego pakietu — używany
/// w jednostkowych testach żeby walidować zachowanie aktualizacji per pakiet.
#[cfg(test)]
fn update_sender_state(seen: &mut TcpDirState, tcp: &TcpSlice, flags: TcpFlags) {
    let seq = tcp.sequence_number();
    let ack = tcp.acknowledgment_number();

    let win_raw = u32::from(tcp.window_size());
    let payload = tcp.payload().len() as u32;

    let syn_fin = u32::from(flags.contains(TcpFlags::SYN)) + u32::from(flags.contains(TcpFlags::FIN));
    let end = seq.wrapping_add(payload).wrapping_add(syn_fin);

    let win_eff = if seen.td_scale > 0 { win_raw << seen.td_scale } else { win_raw }.max(1);

    update_sender_after_accept(seen, end, ack, win_eff);
}

fn update_sender_after_accept(s: &mut TcpDirState, end: u32, ack: u32, win: u32) {
    if s.td_end == 0 || seq_after(end, s.td_end) {
        s.td_end = end;
    }

    let maxend = ack.wrapping_add(win.max(1));

    if s.td_maxend == 0 || seq_after(maxend, s.td_maxend) {
        s.td_maxend = maxend;
    }

    if win > s.td_maxwin { s.td_maxwin = win; }
}

fn record_last(s: &mut TcpDirState, seq: u32, ack: u32, end: u32, win: u32, scale: u8, flags: TcpFlags) {
    s.last_seq = seq;
    s.last_ack = ack;
    s.last_end = end;
    s.last_win = win;
    s.last_wscale = scale;
    s.last_flags = flags.bits();
}

fn sync_last_on_ignore(state: &mut TcpProtoState, tcp: &TcpSlice, flags: TcpFlags, dir: Direction) {
    let seq = tcp.sequence_number();
    let ack = tcp.acknowledgment_number();

    let win_raw = u32::from(tcp.window_size());
    let payload = tcp.payload().len() as u32;

    let syn_fin = u32::from(flags.contains(TcpFlags::SYN)) + u32::from(flags.contains(TcpFlags::FIN));

    let end = seq.wrapping_add(payload).wrapping_add(syn_fin);

    let scale = state.seen[dir as usize].td_scale;

    record_last(&mut state.seen[dir as usize], seq, ack, end, win_raw, scale, flags);
}

fn opposite_dir(d: Direction) -> Direction {
    match d {
        Direction::Original => Direction::Reply,
        Direction::Reply => Direction::Original,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use etherparse::PacketBuilder;
    use std::net::{IpAddr, Ipv4Addr};
    use std::time::{Duration, Instant};

    use crate::conntrack::tuple::FlowTuple;

    const CLIENT_IP: [u8; 4] = [10, 0, 0, 1];
    const SERVER_IP: [u8; 4] = [192, 0, 2, 80];
    const CLIENT_PORT: u16 = 50_000;
    const SERVER_PORT: u16 = 80;

    fn build_from_client<F>(seq: u32, win: u16, build: F) -> Vec<u8> where
        F: FnOnce(etherparse::PacketBuilderStep<etherparse::TcpHeader>) -> etherparse::PacketBuilderStep<etherparse::TcpHeader> {
        let payload = b"";

        let b = PacketBuilder::ipv4(CLIENT_IP, SERVER_IP, 64).tcp(CLIENT_PORT, SERVER_PORT, seq, win);
        let b = build(b);

        let mut buf = Vec::with_capacity(b.size(payload.len()));

        b.write(&mut buf, payload).unwrap();

        buf
    }

    fn build_from_server<F>(seq: u32, win: u16, build: F) -> Vec<u8> where
        F: FnOnce(etherparse::PacketBuilderStep<etherparse::TcpHeader>) -> etherparse::PacketBuilderStep<etherparse::TcpHeader> {
        let payload = b"";

        let b = PacketBuilder::ipv4(SERVER_IP, CLIENT_IP, 64).tcp(SERVER_PORT, CLIENT_PORT, seq, win);
        let b = build(b);

        let mut buf = Vec::with_capacity(b.size(payload.len()));

        b.write(&mut buf, payload).unwrap();

        buf
    }

    /// Buduje TCP slice z surowych bajtów opcji + minimalnego header'a.
    fn tcp_with_options(opts: &[u8]) -> Vec<u8> {
        let pad = (4 - opts.len() % 4) % 4;
        let opts_padded: Vec<u8> = opts.iter().copied().chain(std::iter::repeat(0).take(pad)).collect();
        let data_offset = ((20 + opts_padded.len()) / 4) as u8;

        let mut hdr = vec![
            // src_port
            (CLIENT_PORT >> 8) as u8, CLIENT_PORT as u8,
            // dst_port
            (SERVER_PORT >> 8) as u8, SERVER_PORT as u8,
            // seq=0
            0, 0, 0, 0,
            // ack=0
            0, 0, 0, 0,
            // data offset (4 bity wysokie) + 4 bity rezerwowane
            data_offset << 4, 0,
            // window
            0x16, 0xD0,
            // checksum (placeholder)
            0, 0,
            // urgent
            0, 0,
        ];

        hdr.extend_from_slice(&opts_padded);

        hdr
    }

    fn parse(buf: &[u8]) -> SlicedPacket<'_> {
        SlicedPacket::from_ip(buf).unwrap()
    }

    fn slice_tcp(buf: &[u8]) -> TcpSlice<'_> {
        TcpSlice::from_slice(buf).unwrap()
    }

    fn entry_with(state: TcpProtoState) -> ConntrackEntry {
        let tuple = FlowTuple::new(
            IpAddr::V4(Ipv4Addr::from(CLIENT_IP)),
            CLIENT_PORT,
            IpAddr::V4(Ipv4Addr::from(SERVER_IP)),
            SERVER_PORT,
            Protocol::Tcp,
        );

        ConntrackEntry::new(
            1,
            tuple,
            ProtoState::Tcp(state),
            Duration::from_secs(60),
            0,
        )
    }

    fn extract_state(entry: &ConntrackEntry) -> TcpProtoState {
        let g = entry.proto_state.lock();

        let ProtoState::Tcp(s) = &*g else { panic!("expected TCP state"); };

        s.clone()
    }

    fn cfg_strict() -> ConntrackConfig {
        let mut c = ConntrackConfig::default();

        c.tcp.loose = false;
        c.tcp.be_liberal = false;
        c.tcp.ignore_invalid_rst = false;

        c
    }

    fn cfg_loose() -> ConntrackConfig {
        let mut c = ConntrackConfig::default();

        c.tcp.loose = true;
        c.tcp.be_liberal = true;

        c
    }

    fn syn_packet_seq(seq: u32) -> Vec<u8> {
        build_from_client(seq, 5840, |b| b.syn())
    }

    fn ack_packet(seq: u32, ack: u32, win: u16) -> Vec<u8> {
        build_from_client(seq, win, |b| b.ack(ack))
    }

    fn extract_tcp_slice<'a>(buf: &'a [u8]) -> TcpSlice<'a> {
        let pkt = parse(buf);

        let TransportSlice::Tcp(tcp) = pkt.transport.as_ref().unwrap() else { panic!(); };

        tcp.clone()
    }

    // === Sequence number helpers ===

    #[test]
    fn seq_after_basic() {
        assert!(seq_after(100, 50));
        assert!(!seq_after(50, 100));
        assert!(!seq_after(100, 100));  // strict >
    }

    #[test]
    fn seq_after_wraparound() {
        assert!(seq_after(10, u32::MAX - 100));
        assert!(!seq_after(u32::MAX - 100, 10));
    }

    #[test]
    fn seq_after_half_space_boundary() {
        let b = 0u32;
        let a = (1u32 << 31) - 1;

        assert!(seq_after(a, b));
    }

    // === Flag classification ===

    #[test]
    fn classify_priority_rst_beats_everything() {
        let f = TcpFlags::RST | TcpFlags::ACK | TcpFlags::SYN | TcpFlags::FIN;

        assert_eq!(classify_flags(f), TcpFlagBit::Rst);
    }

    #[test]
    fn classify_priority_fin_beats_syn_ack() {
        let f = TcpFlags::FIN | TcpFlags::SYN | TcpFlags::ACK;

        assert_eq!(classify_flags(f), TcpFlagBit::Fin);
    }

    #[test]
    fn classify_synack_when_syn_and_ack_no_fin_no_rst() {
        assert_eq!(classify_flags(TcpFlags::SYN | TcpFlags::ACK), TcpFlagBit::SynAck);
    }

    #[test]
    fn classify_syn_only() {
        assert_eq!(classify_flags(TcpFlags::SYN), TcpFlagBit::Syn);
    }

    #[test]
    fn classify_ack_only() {
        assert_eq!(classify_flags(TcpFlags::ACK), TcpFlagBit::Ack);
    }

    #[test]
    fn classify_psh_ack_treated_as_ack() {
        // PSH nie wpływa na klasyfikację (data segment).
        assert_eq!(classify_flags(TcpFlags::PSH | TcpFlags::ACK), TcpFlagBit::Ack);
    }

    #[test]
    fn classify_empty_is_none() {
        assert_eq!(classify_flags(TcpFlags::empty()), TcpFlagBit::None);
    }

    #[test]
    fn parse_flags_reads_bits_from_etherparse() {
        let buf = build_from_client(0, 1024, |b| b.syn());

        let pkt = parse(&buf);

        let TransportSlice::Tcp(tcp) = pkt.transport.as_ref().unwrap() else { panic!(); };

        let flags = parse_flags(tcp);

        assert!(flags.contains(TcpFlags::SYN));
        assert!(!flags.contains(TcpFlags::ACK));
    }

    #[test]
    fn parse_flags_reads_synack() {
        let buf = build_from_server(0, 1024, |b| b.syn().ack(1));

        let pkt = parse(&buf);

        let TransportSlice::Tcp(tcp) = pkt.transport.as_ref().unwrap() else { panic!(); };

        let flags = parse_flags(tcp);

        assert!(flags.contains(TcpFlags::SYN));
        assert!(flags.contains(TcpFlags::ACK));
    }

    // === Transition table — kluczowe ścieżki ===

    #[test]
    fn transition_orig_syn_from_none_starts_syn_sent() {
        let t = next_state(Direction::Original, TcpFlagBit::Syn, TcpConntrack::None);

        assert_eq!(t, Transition::To(TcpConntrack::SynSent));
    }

    #[test]
    fn transition_reply_synack_from_syn_sent_advances() {
        let t = next_state(Direction::Reply, TcpFlagBit::SynAck, TcpConntrack::SynSent);

        assert_eq!(t, Transition::To(TcpConntrack::SynRecv));
    }

    #[test]
    fn transition_orig_ack_from_syn_recv_completes_handshake() {
        let t = next_state(Direction::Original, TcpFlagBit::Ack, TcpConntrack::SynRecv);

        assert_eq!(t, Transition::To(TcpConntrack::Established));
    }

    #[test]
    fn transition_orig_synack_from_none_invalid() {
        // Klient nie powinien wysyłać SYN-ACK jako pierwszy pakiet.
        let t = next_state(Direction::Original, TcpFlagBit::SynAck, TcpConntrack::None);

        assert_eq!(t, Transition::Invalid);
    }

    #[test]
    fn transition_reply_synack_in_syn_recv_is_ignore() {
        // Retransmitted SYN-ACK — nie zmieniaj stanu.
        let t = next_state(Direction::Reply, TcpFlagBit::SynAck, TcpConntrack::SynRecv);

        assert_eq!(t, Transition::Ignore);
    }

    #[test]
    fn transition_simultaneous_open() {
        // Klient wysyła SYN, w odpowiedzi serwer też SYN (nie SYN-ACK).
        let t = next_state(Direction::Reply, TcpFlagBit::Syn, TcpConntrack::SynSent);

        assert_eq!(t, Transition::To(TcpConntrack::SynSent2));
    }

    #[test]
    fn transition_fin_from_established_starts_close() {
        let t_orig = next_state(Direction::Original, TcpFlagBit::Fin, TcpConntrack::Established);
        let t_rep  = next_state(Direction::Reply,    TcpFlagBit::Fin, TcpConntrack::Established);

        assert_eq!(t_orig, Transition::To(TcpConntrack::FinWait));
        assert_eq!(t_rep,  Transition::To(TcpConntrack::FinWait));
    }

    #[test]
    fn transition_rst_from_established_closes() {
        let t = next_state(Direction::Original, TcpFlagBit::Rst, TcpConntrack::Established);

        assert_eq!(t, Transition::To(TcpConntrack::Close));
    }

    #[test]
    fn transition_rst_from_none_invalid() {
        // Brak flow → RST nie ma sensu.
        let t = next_state(Direction::Original, TcpFlagBit::Rst, TcpConntrack::None);

        assert_eq!(t, Transition::Invalid);
    }

    #[test]
    fn transition_none_flags_always_invalid() {
        for dir in [Direction::Original, Direction::Reply] {
            for state in [
                TcpConntrack::None,
                TcpConntrack::SynSent,
                TcpConntrack::Established,
                TcpConntrack::TimeWait,
                TcpConntrack::Close,
            ] {
                let t = next_state(dir, TcpFlagBit::None, state);

                assert_eq!(t, Transition::Invalid, "dir={:?} state={:?}", dir, state);
            }
        }
    }

    #[test]
    fn transition_table_dimensions() {
        // Sanity check rozmiarów tabeli — dziedzina i przeciwdziedzina.
        assert_eq!(TRANSITIONS.len(), 2);            // 2 directions
        assert_eq!(TRANSITIONS[0].len(), 6);         // 6 flag bits
        assert_eq!(TRANSITIONS[0][0].len(), 10);     // 10 stanów
    }

    // === Handler::new_state ===

    #[test]
    fn new_state_syn_starts_syn_sent() {
        let buf = build_from_client(1000, 5840, |b| b.syn());

        let pkt = parse(&buf);

        let h = TcpHandler::new(Arc::new(ObserverRegistry::default()));

        let state = h.new_state(&pkt, Direction::Original, &cfg_strict()).unwrap();

        let NewStateOutcome::State(ProtoState::Tcp(s)) = state else { panic!(); };

        assert_eq!(s.state, TcpConntrack::SynSent);
        assert_eq!(s.last_dir, Some(Direction::Original));
        assert_eq!(s.retrans, 0);
        assert_eq!(s.last_index, TcpFlagBit::Syn);
    }

    #[test]
    fn new_state_syn_initializes_seen_with_seq_plus_one() {
        // SYN konsumuje 1 numer seq mimo zero payloadu.
        let buf = build_from_client(1000, 5840, |b| b.syn());

        let pkt = parse(&buf);

        let h = TcpHandler::new(Arc::new(ObserverRegistry::default()));

        let state = h.new_state(&pkt, Direction::Original, &cfg_strict()).unwrap();

        let NewStateOutcome::State(ProtoState::Tcp(s)) = state else { panic!(); };

        assert_eq!(s.seen[0].td_end, 1001);   // seq + 1 (SYN counts)
        assert_eq!(s.seen[0].td_maxwin, 5840);
    }

    #[test]
    fn new_state_strict_rejects_ack_only() {
        let buf = build_from_client(1000, 5840, |b| b.ack(1));

        let pkt = parse(&buf);

        let h = TcpHandler::new(Arc::new(ObserverRegistry::default()));

        let r = h.new_state(&pkt, Direction::Original, &cfg_strict());

        assert!(matches!(r, Err(NewStateError::InvalidFirst { .. })));
    }

    #[test]
    fn new_state_loose_accepts_ack_as_established() {
        let buf = build_from_client(1000, 5840, |b| b.ack(1));

        let pkt = parse(&buf);

        let h = TcpHandler::new(Arc::new(ObserverRegistry::default()));

        let state = h.new_state(&pkt, Direction::Original, &cfg_loose()).unwrap();

        let NewStateOutcome::State(ProtoState::Tcp(s)) = state else { panic!(); };

        assert_eq!(s.state, TcpConntrack::Established);
    }

    #[test]
    fn new_state_loose_accepts_synack_as_established() {
        let buf = build_from_client(1000, 5840, |b| b.syn().ack(1));

        let pkt = parse(&buf);

        let h = TcpHandler::new(Arc::new(ObserverRegistry::default()));

        let state = h.new_state(&pkt, Direction::Original, &cfg_loose()).unwrap();

        let NewStateOutcome::State(ProtoState::Tcp(s)) = state else { panic!(); };

        assert_eq!(s.state, TcpConntrack::Established);
    }

    #[test]
    fn new_state_strict_rejects_fin() {
        let buf = build_from_client(1000, 5840, |b| b.fin());

        let pkt = parse(&buf);

        let h = TcpHandler::new(Arc::new(ObserverRegistry::default()));

        assert!(h.new_state(&pkt, Direction::Original, &cfg_strict()).is_err());
    }

    #[test]
    fn new_state_strict_rejects_rst() {
        let buf = build_from_client(1000, 5840, |b| b.rst());

        let pkt = parse(&buf);

        let h = TcpHandler::new(Arc::new(ObserverRegistry::default()));

        assert!(h.new_state(&pkt, Direction::Original, &cfg_strict()).is_err());
    }

    #[test]
    fn new_state_missing_transport_returns_error() {
        // Buduj pakiet IP bez TCP — etherparse dostarczy raw IP payload.
        // Hack: zbuduj UDP pakiet i sparsuj jako TCP slice — handler zrobi InvalidFirst.
        let payload = b"";

        let b = PacketBuilder::ipv4(CLIENT_IP, SERVER_IP, 64).udp(CLIENT_PORT, SERVER_PORT);

        let mut buf = Vec::with_capacity(b.size(payload.len()));

        b.write(&mut buf, payload).unwrap();

        let pkt = parse(&buf);

        let h = TcpHandler::new(Arc::new(ObserverRegistry::default()));

        let r = h.new_state(&pkt, Direction::Original, &cfg_strict());

        assert!(matches!(r, Err(NewStateError::InvalidFirst { reason: "transport is not TCP", .. })));
    }

    // === Handler::update ===

    #[test]
    fn full_handshake_reaches_established() {
        let h = TcpHandler::new(Arc::new(ObserverRegistry::default()));
        let cfg = cfg_strict();

        // 1. Klient wysyła SYN
        let syn = build_from_client(1000, 5840, |b| b.syn());
        let pkt = parse(&syn);

        let initial = h.new_state(&pkt, Direction::Original, &cfg).unwrap();

        let NewStateOutcome::State(ProtoState::Tcp(s)) = initial else { panic!(); };

        let entry = entry_with(s);

        // 2. Serwer wysyła SYN-ACK
        let synack = build_from_server(2000, 5840, |b| b.syn().ack(1001));
        let pkt = parse(&synack);

        assert_eq!(
            h.update(&entry, &pkt, Direction::Reply, Instant::now(), &cfg, PacketId(0)),
            CtVerdict::Accept
        );
        assert_eq!(extract_state(&entry).state, TcpConntrack::SynRecv);

        // 3. Klient wysyła ACK — handshake done
        let ack = build_from_client(1001, 5840, |b| b.ack(2001));
        let pkt = parse(&ack);

        assert_eq!(
            h.update(&entry, &pkt, Direction::Original, Instant::now(), &cfg, PacketId(0)),
            CtVerdict::Accept
        );
        assert_eq!(extract_state(&entry).state, TcpConntrack::Established);
    }

    #[test]
    fn full_close_sequence_reaches_time_wait() {
        let h = TcpHandler::new(Arc::new(ObserverRegistry::default()));

        let cfg = cfg_strict();

        let entry = entry_with(TcpProtoState {
            state: TcpConntrack::Established,
            last_dir: Some(Direction::Original),
            ..Default::default()
        });

        // FIN od klienta
        let fin = build_from_client(1001, 5840, |b| b.fin().ack(2001));
        let pkt = parse(&fin);

        h.update(&entry, &pkt, Direction::Original, Instant::now(), &cfg, PacketId(0));

        assert_eq!(extract_state(&entry).state, TcpConntrack::FinWait);

        // ACK od serwera
        let ack = build_from_server(2001, 5840, |b| b.ack(1002));
        let pkt = parse(&ack);

        h.update(&entry, &pkt, Direction::Reply, Instant::now(), &cfg, PacketId(0));

        assert_eq!(extract_state(&entry).state, TcpConntrack::CloseWait);

        // FIN od serwera
        let fin2 = build_from_server(2001, 5840, |b| b.fin().ack(1002));
        let pkt = parse(&fin2);

        h.update(&entry, &pkt, Direction::Reply, Instant::now(), &cfg, PacketId(0));

        assert_eq!(extract_state(&entry).state, TcpConntrack::LastAck);

        // ACK od klienta — TIME_WAIT
        let ack2 = build_from_client(1002, 5840, |b| b.ack(2002));
        let pkt = parse(&ack2);

        h.update(&entry, &pkt, Direction::Original, Instant::now(), &cfg, PacketId(0));

        assert_eq!(extract_state(&entry).state, TcpConntrack::TimeWait);
    }

    #[test]
    fn rst_in_established_goes_to_close() {
        // Strict mode wymaga RST z seq == receiver.td_end (RFC 5961). Tu dajemy
        // receiverowi td_end=1000 i RST też ma seq=1000 — walidacja przechodzi.
        let h = TcpHandler::new(Arc::new(ObserverRegistry::default()));

        let mut seen_reply = TcpDirState::default();
        seen_reply.td_end = 1000;
        seen_reply.td_maxwin = 5840;

        let entry = entry_with(TcpProtoState {
            state: TcpConntrack::Established,
            seen: [TcpDirState::default(), seen_reply],
            ..Default::default()
        });

        let rst = build_from_client(1000, 0, |b| b.rst());
        let pkt = parse(&rst);

        h.update(&entry, &pkt, Direction::Original, Instant::now(), &cfg_strict(), PacketId(0));

        assert_eq!(extract_state(&entry).state, TcpConntrack::Close);
    }

    #[test]
    fn ack_in_syn_sent_orig_invalid_strict() {
        // Klient wysłał SYN, potem od razu wysyła ACK bez czekania na SYN-ACK — Invalid.
        let h = TcpHandler::new(Arc::new(ObserverRegistry::default()));

        let entry = entry_with(TcpProtoState {
            state: TcpConntrack::SynSent,
            last_dir: Some(Direction::Original),
            ..Default::default()
        });

        let ack = build_from_client(1001, 5840, |b| b.ack(1));
        let pkt = parse(&ack);

        let v = h.update(&entry, &pkt, Direction::Original, Instant::now(), &cfg_strict(), PacketId(0));

        assert_eq!(v, CtVerdict::Invalid);
        // Stan nie zmienił się
        assert_eq!(extract_state(&entry).state, TcpConntrack::SynSent);
    }

    #[test]
    fn ack_in_syn_sent_orig_be_liberal_accept() {
        // Liberal mode przepuszcza ten sam scenariusz.
        let h = TcpHandler::new(Arc::new(ObserverRegistry::default()));

        let entry = entry_with(TcpProtoState {
            state: TcpConntrack::SynSent,
            last_dir: Some(Direction::Original),
            ..Default::default()
        });

        let ack = build_from_client(1001, 5840, |b| b.ack(1));
        let pkt = parse(&ack);

        let v = h.update(&entry, &pkt, Direction::Original, Instant::now(), &cfg_loose(), PacketId(0));

        assert_eq!(v, CtVerdict::Accept);
    }

    #[test]
    fn retransmitted_synack_returns_accept_without_state_change() {
        // SYN-ACK retransmit w SynRecv — Ignore → Accept, stan zostaje.
        let h = TcpHandler::new(Arc::new(ObserverRegistry::default()));

        let entry = entry_with(TcpProtoState {
            state: TcpConntrack::SynRecv,
            ..Default::default()
        });

        let synack = build_from_server(2000, 5840, |b| b.syn().ack(1001));
        let pkt = parse(&synack);
        let v = h.update(&entry, &pkt, Direction::Reply, Instant::now(), &cfg_strict(), PacketId(0));

        assert_eq!(v, CtVerdict::Accept);
        assert_eq!(extract_state(&entry).state, TcpConntrack::SynRecv);
    }

    #[test]
    fn retransmission_counter_increments_on_duplicate() {
        // Linux-style retrans: porównujemy seq/ack/end/win/flags. Pierwszy pakiet
        // ustawia baseline (retrans=0), kolejne IDENTYCZNE pakiety podbijają retrans.
        let h = TcpHandler::new(Arc::new(ObserverRegistry::default()));

        let entry = entry_with(TcpProtoState {
            state: TcpConntrack::SynSent,
            last_dir: Some(Direction::Original),
            last_index: TcpFlagBit::Syn,
            retrans: 0,
            ..Default::default()
        });

        let syn = build_from_client(1000, 5840, |b| b.syn());
        let pkt = parse(&syn);

        // Pierwszy SYN — baseline, retrans=0.
        h.update(&entry, &pkt, Direction::Original, Instant::now(), &cfg_strict(), PacketId(0));
        assert_eq!(extract_state(&entry).retrans, 0);

        // Drugi identyczny SYN — retrans=1.
        h.update(&entry, &pkt, Direction::Original, Instant::now(), &cfg_strict(), PacketId(0));
        assert_eq!(extract_state(&entry).retrans, 1);

        // Trzeci raz — retrans=2.
        h.update(&entry, &pkt, Direction::Original, Instant::now(), &cfg_strict(), PacketId(0));
        assert_eq!(extract_state(&entry).retrans, 2);
    }

    #[test]
    fn retransmission_counter_resets_on_different_packet() {
        let h = TcpHandler::new(Arc::new(ObserverRegistry::default()));

        let entry = entry_with(TcpProtoState {
            state: TcpConntrack::SynRecv,
            last_dir: Some(Direction::Original),
            last_index: TcpFlagBit::Syn,
            retrans: 5,
            ..Default::default()
        });

        // ACK po SYN-RECV — inne flagi → retrans → 0.
        let ack = build_from_client(1001, 5840, |b| b.ack(2001));
        let pkt = parse(&ack);

        h.update(&entry, &pkt, Direction::Original, Instant::now(), &cfg_strict(), PacketId(0));

        assert_eq!(extract_state(&entry).retrans, 0);
    }

    #[test]
    fn update_with_non_tcp_packet_invalid() {
        let h = TcpHandler::new(Arc::new(ObserverRegistry::default()));

        let entry = entry_with(TcpProtoState::default());

        let payload = b"";

        let b = PacketBuilder::ipv4(CLIENT_IP, SERVER_IP, 64).udp(CLIENT_PORT, SERVER_PORT);

        let mut buf = Vec::with_capacity(b.size(payload.len()));

        b.write(&mut buf, payload).unwrap();

        let pkt = parse(&buf);
        let v = h.update(&entry, &pkt, Direction::Original, Instant::now(), &cfg_strict(), PacketId(0));

        assert_eq!(v, CtVerdict::Invalid);
    }

    // === Handler::timeout ===

    #[test]
    fn timeout_per_state() {
        let h = TcpHandler::new(Arc::new(ObserverRegistry::default()));

        let cfg = ConntrackConfig::default();

        let cases = [
            (TcpConntrack::None,        cfg.generic_timeout),
            (TcpConntrack::SynSent,     cfg.tcp.timeout.syn_sent),
            (TcpConntrack::SynSent2,    cfg.tcp.timeout.syn_sent),
            (TcpConntrack::SynRecv,     cfg.tcp.timeout.syn_recv),
            (TcpConntrack::Established, cfg.tcp.timeout.established),
            (TcpConntrack::FinWait,     cfg.tcp.timeout.fin_wait),
            (TcpConntrack::CloseWait,   cfg.tcp.timeout.close_wait),
            (TcpConntrack::LastAck,     cfg.tcp.timeout.last_ack),
            (TcpConntrack::TimeWait,    cfg.tcp.timeout.time_wait),
            (TcpConntrack::Close,       cfg.tcp.timeout.close),
        ];

        for (state, expected) in cases {
            let s = ProtoState::Tcp(TcpProtoState { state, ..Default::default() });
            assert_eq!(h.timeout(&s, &cfg), expected, "state {:?}", state);
        }
    }

    #[test]
    fn timeout_established_with_excessive_retrans_uses_max_retrans() {
        let h = TcpHandler::new(Arc::new(ObserverRegistry::default()));

        let cfg = ConntrackConfig::default();

        let s = ProtoState::Tcp(TcpProtoState {
            state: TcpConntrack::Established,
            retrans: cfg.tcp.max_retrans + 1,
            ..Default::default()
        });

        assert_eq!(h.timeout(&s, &cfg), cfg.tcp.timeout.max_retrans);
    }

    #[test]
    fn timeout_fallback_for_non_tcp_state() {
        // Defensywne: jeśli ktoś wsadził Udp state w TCP handler.
        let h = TcpHandler::new(Arc::new(ObserverRegistry::default()));

        let cfg = ConntrackConfig::default();

        let s = ProtoState::Udp(crate::conntrack::proto::udp::UdpProtoState::default());

        assert_eq!(h.timeout(&s, &cfg), cfg.tcp.timeout.established);
    }

    // === Handler::is_assured ===

    #[test]
    fn is_assured_only_for_established_and_after() {
        let h = TcpHandler::new(Arc::new(ObserverRegistry::default()));

        let cases = [
            (TcpConntrack::None,        false),
            (TcpConntrack::SynSent,     false),
            (TcpConntrack::SynSent2,    false),
            (TcpConntrack::SynRecv,     false),
            (TcpConntrack::Established, true),
            (TcpConntrack::FinWait,     true),
            (TcpConntrack::CloseWait,   true),
            (TcpConntrack::LastAck,     true),
            (TcpConntrack::TimeWait,    true),
            (TcpConntrack::Close,       false),
        ];

        for (state, expected) in cases {
            let s = ProtoState::Tcp(TcpProtoState { state, ..Default::default() });

            assert_eq!(h.is_assured(&s), expected, "state {:?}", state);
        }
    }

    #[test]
    fn is_assured_false_for_non_tcp_state() {
        let h = TcpHandler::new(Arc::new(ObserverRegistry::default()));
        let s = ProtoState::Udp(crate::conntrack::proto::udp::UdpProtoState::default());

        assert!(!h.is_assured(&s));
    }

    // === TCP options parsing ===

    #[test]
    fn parse_options_empty() {
        let buf = tcp_with_options(&[]);

        let tcp = slice_tcp(&buf);

        let info = parse_options(&tcp);

        assert_eq!(info.window_scale, None);
        assert!(!info.sack_permitted);
    }

    #[test]
    fn parse_options_only_nops() {
        let buf = tcp_with_options(&[1, 1, 1, 1]);  // 4×NOP

        let tcp = slice_tcp(&buf);

        let info = parse_options(&tcp);

        assert_eq!(info.window_scale, None);
        assert!(!info.sack_permitted);
    }

    #[test]
    fn parse_options_eol_stops_parsing() {
        // EOL=0, potem śmieci których nie czytamy.
        let buf = tcp_with_options(&[0, 3, 3, 7]);

        let tcp = slice_tcp(&buf);

        let info = parse_options(&tcp);

        assert_eq!(info.window_scale, None);  // EOL przerwał, WS niezauważone
    }

    #[test]
    fn parse_options_window_scale_extracted() {
        // Kind=3 (WS), Len=3, scale=7.
        let buf = tcp_with_options(&[3, 3, 7]);

        let tcp = slice_tcp(&buf);

        let info = parse_options(&tcp);

        assert_eq!(info.window_scale, Some(7));
    }

    #[test]
    fn parse_options_window_scale_clamped_to_14() {
        // RFC 7323: scale > 14 → clamp do 14.
        let buf = tcp_with_options(&[3, 3, 30]);

        let tcp = slice_tcp(&buf);

        let info = parse_options(&tcp);

        assert_eq!(info.window_scale, Some(14));
    }

    #[test]
    fn parse_options_sack_permitted() {
        // Kind=4 (SACK_PERM), Len=2.
        let buf = tcp_with_options(&[4, 2]);

        let tcp = slice_tcp(&buf);

        let info = parse_options(&tcp);

        assert!(info.sack_permitted);
    }

    #[test]
    fn parse_options_mss_skipped_correctly() {
        // MSS (kind=2, len=4, value=1460) potem SACK_PERM (kind=4, len=2).
        let buf = tcp_with_options(&[2, 4, 0x05, 0xB4, 4, 2]);

        let tcp = slice_tcp(&buf);

        let info = parse_options(&tcp);

        assert!(info.sack_permitted);  // dotarło po przeskoku MSS
    }

    #[test]
    fn parse_options_typical_syn_combination() {
        // MSS=1460, SACK_PERM, NOP, NOP, WS=7
        let buf = tcp_with_options(&[2, 4, 0x05, 0xB4, 4, 2, 1, 1, 3, 3, 7]);

        let tcp = slice_tcp(&buf);

        let info = parse_options(&tcp);

        assert_eq!(info.window_scale, Some(7));
        assert!(info.sack_permitted);
    }

    #[test]
    fn parse_options_malformed_zero_length_breaks() {
        // Niepoprawna opcja: kind=99, len=0 → infinite loop bez break.
        let buf = tcp_with_options(&[99, 0, 0xDE, 0xAD]);

        let tcp = slice_tcp(&buf);

        let _info = parse_options(&tcp);  // nie zawiesi się
    }

    #[test]
    fn parse_options_truncated_window_scale_break() {
        // WS oczekuje 3 bajty, dostarczamy 2.
        let buf = tcp_with_options(&[3, 3]);  // bez wartości scale

        let tcp = slice_tcp(&buf);

        let info = parse_options(&tcp);

        assert_eq!(info.window_scale, Some(0));
    }

    #[test]
    fn parse_options_unknown_option_skipped() {
        // Nieznana opcja kind=8 (Timestamps), len=10. Po niej WS.
        let buf = tcp_with_options(&[8, 10, 0, 0, 0, 0, 0, 0, 0, 0, 3, 3, 5]);

        let tcp = slice_tcp(&buf);

        let info = parse_options(&tcp);

        assert_eq!(info.window_scale, Some(5));
    }

    // === update_sender_state ===

    #[test]
    fn update_sender_state_initializes_from_zero() {
        let mut seen = TcpDirState::default();

        let buf = syn_packet_seq(1000);

        let tcp = extract_tcp_slice(&buf);

        update_sender_state(&mut seen, &tcp, parse_flags(&tcp));

        // SYN konsumuje 1 seq → td_end = 1001.
        assert_eq!(seen.td_end, 1001);
        // td_maxwin ≥ raw window (5840) bo bez scale.
        assert!(seen.td_maxwin >= 5840);
    }

    #[test]
    fn update_sender_state_advances_only_forward() {
        let mut seen = TcpDirState { td_end: 5000, td_maxwin: 4000, ..Default::default() };

        // Pakiet z mniejszym seq (retransmit) nie powinien cofać td_end.
        let buf = ack_packet(2000, 0, 4000);
        let tcp = extract_tcp_slice(&buf);

        update_sender_state(&mut seen, &tcp, parse_flags(&tcp));

        assert_eq!(seen.td_end, 5000);  // bez zmian
    }

    #[test]
    fn update_sender_state_handles_wraparound() {
        let mut seen = TcpDirState {
            td_end: u32::MAX - 100,
            td_maxwin: 1000,
            ..Default::default()
        };

        // Pakiet z seq=50 (po wraparound).
        let buf = ack_packet(50, 0, 1000);
        let tcp = extract_tcp_slice(&buf);

        update_sender_state(&mut seen, &tcp, parse_flags(&tcp));

        // td_end powinno przejść na nową wartość bo seq_after po wraparound.
        assert_eq!(seen.td_end, 50);
    }

    #[test]
    fn update_sender_state_zero_window_treated_as_one() {
        let mut seen = TcpDirState::default();

        let buf = ack_packet(1000, 0, 0);  // win = 0
        let tcp = extract_tcp_slice(&buf);

        update_sender_state(&mut seen, &tcp, parse_flags(&tcp));

        // win_eff = max(0, 1) = 1, więc maxend = ack + 1.
        assert!(seen.td_maxwin >= 1);
    }

    #[test]
    fn update_sender_state_uses_window_scale() {
        let mut seen = TcpDirState { td_scale: 7, ..Default::default() };

        let buf = ack_packet(1000, 0, 100);  // raw win = 100
        let tcp = extract_tcp_slice(&buf);

        update_sender_state(&mut seen, &tcp, parse_flags(&tcp));

        // win_eff = 100 << 7 = 12800.
        assert_eq!(seen.td_maxwin, 12800);
    }

    #[test]
    fn update_sender_state_records_max_window() {
        let mut seen = TcpDirState { td_maxwin: 10_000, ..Default::default() };

        // Pakiet z mniejszym window — nie obniżamy max.
        let buf = ack_packet(1000, 0, 5000);
        let tcp = extract_tcp_slice(&buf);

        update_sender_state(&mut seen, &tcp, parse_flags(&tcp));

        assert_eq!(seen.td_maxwin, 10_000);  // niezmienione
    }

    #[test]
    fn update_sender_state_fin_consumes_one_seq() {
        let mut seen = TcpDirState::default();

        let buf = build_from_client(1000, 5840, |b| b.fin().ack(1));
        let tcp = extract_tcp_slice(&buf);

        update_sender_state(&mut seen, &tcp, parse_flags(&tcp));

        // FIN konsumuje 1 jak SYN → td_end = 1001.
        assert_eq!(seen.td_end, 1001);
    }
}
