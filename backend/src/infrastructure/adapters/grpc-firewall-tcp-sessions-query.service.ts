import { Injectable } from '@nestjs/common';
import type { ConntrackFlowDto, ConntrackFlowStateDto } from '../../application/dtos/conntrack-metrics.dto.js';
import type { IFirewallTcpSessionsQueryService } from '../../application/ports/firewall-tcp-sessions-query-service.interface.js';
import {
  TcpSessionEndpoint,
  TcpTrackedSession,
  type TcpTrackedSessionDetails,
  type TcpTrackedSessionState,
} from '../../domain/entities/tcp-tracked-session.entity.js';
import { IpAddress } from '../../domain/value-objects/ip-address.vo.js';
import { Port } from '../../domain/value-objects/port.vo.js';
import { GrpcFirewallConntrackMetricsStreamService } from './grpc-firewall-conntrack-metrics-stream.service.js';

@Injectable()
export class GrpcFirewallTcpSessionsQueryService
  implements IFirewallTcpSessionsQueryService
{
  constructor(
    private readonly conntrackStream: GrpcFirewallConntrackMetricsStreamService,
  ) {}

  async getTcpSessions(): Promise<TcpTrackedSession[]> {
    const update = await this.conntrackStream.getConntrackMetricsSnapshot();

    return update.flows
      .filter(
        (flow) => flow.original.protocol === 'tcp' && flow.lifecycle === 'active',
      )
      .map((flow) => this.toTcpTrackedSession(flow));
  }

  private toTcpTrackedSession(flow: ConntrackFlowDto): TcpTrackedSession {
    const endpointA = TcpSessionEndpoint.create(
      IpAddress.create(flow.original.srcIp),
      Port.create(flow.original.srcPort),
    );

    const endpointB = TcpSessionEndpoint.create(
      IpAddress.create(flow.original.dstIp),
      Port.create(flow.original.dstPort),
    );

    return TcpTrackedSession.create(
      endpointA,
      endpointB,
      this.toSessionState(flow.state),
      this.toSessionDetails(flow),
    );
  }

  private toSessionDetails(flow: ConntrackFlowDto): TcpTrackedSessionDetails {
    return {
      id: flow.id,
      lifecycle: flow.lifecycle,
      lastDirection: flow.lastDirection,
      interfaces: flow.interfaces,
      mark: flow.mark,
      statusBits: flow.statusBits,
      bytesOriginal: flow.bytesOriginal,
      bytesReply: flow.bytesReply,
      packetsOriginal: flow.packetsOriginal,
      packetsReply: flow.packetsReply,
      createdAt: flow.createdAt,
      lastSeenAt: flow.lastSeenAt,
      expiresAt: flow.expiresAt,
      destroyedAt: flow.destroyedAt,
      destroyReason: flow.destroyReason,
      natInfo: flow.natInfo,
    };
  }

  private toSessionState(state: ConntrackFlowStateDto): TcpTrackedSessionState {
    switch (state) {
      case 'new':
        return 'syn_sent';
      case 'established':
        return 'established';
      case 'related':
        return 'established';
      case 'invalid':
        return 'unknown';
      default:
        return 'unspecified';
    }
  }
}
