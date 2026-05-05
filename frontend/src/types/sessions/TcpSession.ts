export type TcpTrackedSessionState =
  | "unspecified"
  | "syn_sent"
  | "syn_ack_received"
  | "established"
  | "fin_sent"
  | "ack_sent"
  | "ack_fin_sent"
  | "time_wait"
  | "closed"
  | "unknown";

export interface TcpSessionEndpoint {
  ip: string;
  port: number;
}

export interface TcpTrackedSession {
  endpointA: TcpSessionEndpoint;
  endpointB: TcpSessionEndpoint;
  state: TcpTrackedSessionState;
}
