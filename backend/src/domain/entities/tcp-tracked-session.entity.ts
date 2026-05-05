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
  ) {}

  public static create(
    endpointA: TcpSessionEndpoint,
    endpointB: TcpSessionEndpoint,
    state: TcpTrackedSessionState,
  ): TcpTrackedSession {
    return new TcpTrackedSession(endpointA, endpointB, state);
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
}
