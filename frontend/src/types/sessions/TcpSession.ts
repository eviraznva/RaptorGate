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

export type TcpTrackedSessionLifecycle = "active" | "destroyed" | "unspecified";
export type TcpTrackedSessionDirection = "original" | "reply" | "unspecified";
export type TcpTrackedSessionDestroyReason =
  | "timeout"
  | "manual"
  | "replaced"
  | "shutdown"
  | "unspecified";

export interface TcpSessionEndpoint {
  ip: string;
  port: number;
}

export interface TcpTrackedSessionInterfaces {
  originalIngress: string;
  originalEgress: string;
  replyIngress: string;
  replyEgress: string;
}

export interface TcpTrackedSessionNatInfo {
  ruleId: string;
  bindingId: string;
  hasSrcNat: boolean;
  hasDstNat: boolean;
  allocatedIp?: string;
  allocatedPort?: number;
  srcManipIp?: string;
  srcManipPort?: number;
  dstManipIp?: string;
  dstManipPort?: number;
}

export interface TcpTrackedSession {
  id: string;
  endpointA: TcpSessionEndpoint;
  endpointB: TcpSessionEndpoint;
  state: TcpTrackedSessionState;
  lifecycle: TcpTrackedSessionLifecycle;
  lastDirection: TcpTrackedSessionDirection;
  interfaces: TcpTrackedSessionInterfaces;
  mark: number;
  statusBits: number;
  bytesOriginal: number;
  bytesReply: number;
  packetsOriginal: number;
  packetsReply: number;
  createdAt: string;
  lastSeenAt: string;
  expiresAt: string;
  destroyedAt?: string;
  destroyReason: TcpTrackedSessionDestroyReason;
  natInfo?: TcpTrackedSessionNatInfo;
}
