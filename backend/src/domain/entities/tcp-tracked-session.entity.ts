import { IpAddress } from '../value-objects/ip-address.vo.js';
import { Port } from '../value-objects/port.vo.js';

export type TcpTrackedSessionState =
  | 'unspecified'
  | 'syn_sent'
  | 'syn_ack_received'
  | 'established'
  | 'fin_sent'
  | 'ack_sent'
  | 'ack_fin_sent'
  | 'time_wait'
  | 'closed'
  | 'unknown';

export type TcpTrackedSessionLifecycle = 'active' | 'destroyed' | 'unspecified';
export type TcpTrackedSessionDirection = 'original' | 'reply' | 'unspecified';
export type TcpTrackedSessionDestroyReason =
  | 'timeout'
  | 'manual'
  | 'replaced'
  | 'shutdown'
  | 'unspecified';

export type TcpTrackedSessionInterfaces = {
  originalIngress: string;
  originalEgress: string;
  replyIngress: string;
  replyEgress: string;
};

export type TcpTrackedSessionNatInfo = {
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

export type TcpTrackedSessionDetails = {
  id: string;
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
};

export class TcpSessionEndpoint {
  private constructor(
    private readonly ipAddress: IpAddress,
    private readonly port: Port,
  ) {}

  public static create(ipAddress: IpAddress, port: Port): TcpSessionEndpoint {
    return new TcpSessionEndpoint(ipAddress, port);
  }

  public getIpAddress(): IpAddress {
    return this.ipAddress;
  }

  public getPort(): Port {
    return this.port;
  }
}

export class TcpTrackedSession {
  private constructor(
    private readonly endpointA: TcpSessionEndpoint,
    private readonly endpointB: TcpSessionEndpoint,
    private readonly state: TcpTrackedSessionState,
    private readonly details: TcpTrackedSessionDetails,
  ) {}

  public static create(
    endpointA: TcpSessionEndpoint,
    endpointB: TcpSessionEndpoint,
    state: TcpTrackedSessionState,
    details: TcpTrackedSessionDetails,
  ): TcpTrackedSession {
    return new TcpTrackedSession(endpointA, endpointB, state, details);
  }

  public getEndpointA(): TcpSessionEndpoint {
    return this.endpointA;
  }

  public getEndpointB(): TcpSessionEndpoint {
    return this.endpointB;
  }

  public getState(): TcpTrackedSessionState {
    return this.state;
  }

  public getDetails(): TcpTrackedSessionDetails {
    return this.details;
  }
}
