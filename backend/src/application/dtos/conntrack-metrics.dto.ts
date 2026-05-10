export type ConntrackMetricsUpdateDto = {
  timestamp: string;
  summary?: ConntrackSummaryDto;
  flows: ConntrackFlowDto[];
};

export type ConntrackSummaryDto = {
  created: number;
  confirmed: number;
  destroyed: number;
  invalid: number;
  dropsTableFull: number;
  lookups: number;
  hits: number;
  insertCollisions: number;
  activeEntries: number;
  retainedDestroyedEntries: number;
  historyLimit: number;
};

export type ConntrackFlowDto = {
  id: string;
  lifecycle: ConntrackLifecycleDto;
  state: ConntrackFlowStateDto;
  lastDirection: ConntrackDirectionDto;
  original: ConntrackFlowTupleDto;
  reply: ConntrackFlowTupleDto;
  interfaces: ConntrackInterfacePathDto;
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
  destroyReason: ConntrackDestroyReasonDto;
  natInfo?: ConntrackNatInfoDto;
};

export type ConntrackFlowTupleDto = {
  srcIp: string;
  srcPort: number;
  dstIp: string;
  dstPort: number;
  protocol: ConntrackProtocolDto;
};

export type ConntrackInterfacePathDto = {
  originalIngress: string;
  originalEgress: string;
  replyIngress: string;
  replyEgress: string;
};

export type ConntrackNatInfoDto = {
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
};

export type ConntrackLifecycleDto = "active" | "destroyed" | "unspecified";
export type ConntrackFlowStateDto = "new" | "established" | "related" | "invalid" | "unspecified";
export type ConntrackDirectionDto = "original" | "reply" | "unspecified";
export type ConntrackProtocolDto = "tcp" | "udp" | "icmp" | "icmpv6" | "unknown";
export type ConntrackDestroyReasonDto = "timeout" | "manual" | "replaced" | "shutdown" | "unspecified";
