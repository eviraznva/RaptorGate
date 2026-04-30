import type {
  TcpTrackedSession,
  TcpTrackedSessionState,
} from "../../types/sessions/TcpSession";

export const TCP_SESSION_STATE_LABELS: Record<TcpTrackedSessionState, string> =
  {
    unspecified: "UNSPECIFIED",
    syn_sent: "SYN SENT",
    syn_ack_received: "SYN ACK",
    established: "ESTABLISHED",
    fin_sent: "FIN SENT",
    ack_sent: "ACK SENT",
    ack_fin_sent: "ACK FIN",
    time_wait: "TIME WAIT",
    closed: "CLOSED",
    unknown: "UNKNOWN",
  };

export const TCP_SESSION_STATES = Object.keys(
  TCP_SESSION_STATE_LABELS,
) as TcpTrackedSessionState[];

export function formatEndpoint(session: TcpTrackedSession, side: "A" | "B") {
  const endpoint = side === "A" ? session.endpointA : session.endpointB;

  return `${endpoint.ip}:${endpoint.port}`;
}

export function countByState(
  sessions: TcpTrackedSession[],
  state: TcpTrackedSessionState,
) {
  return sessions.reduce(
    (count, session) => count + (session.state === state ? 1 : 0),
    0,
  );
}

export function getClosingCount(sessions: TcpTrackedSession[]) {
  return sessions.reduce(
    (count, session) =>
      count +
      (session.state === "fin_sent" ||
      session.state === "ack_sent" ||
      session.state === "ack_fin_sent" ||
      session.state === "time_wait"
        ? 1
        : 0),
    0,
  );
}

export function getHandshakeCount(sessions: TcpTrackedSession[]) {
  return sessions.reduce(
    (count, session) =>
      count +
      (session.state === "syn_sent" || session.state === "syn_ack_received"
        ? 1
        : 0),
    0,
  );
}

export function getEstablishedRatio(sessions: TcpTrackedSession[]) {
  if (sessions.length === 0) return 0;

  return Math.round((countByState(sessions, "established") / sessions.length) * 100);
}
