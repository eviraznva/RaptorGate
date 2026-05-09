import {
  Injectable,
  OnModuleDestroy,
  OnModuleInit,
} from '@nestjs/common';
import { Subscription } from 'rxjs';
import type { ConntrackFlowDto, ConntrackFlowStateDto } from '../../application/dtos/conntrack-metrics.dto.js';
import type { IFirewallTcpSessionsQueryService } from '../../application/ports/firewall-tcp-sessions-query-service.interface.js';
import {
  TcpSessionEndpoint,
  TcpTrackedSession,
  type TcpTrackedSessionState,
} from '../../domain/entities/tcp-tracked-session.entity.js';
import { IpAddress } from '../../domain/value-objects/ip-address.vo.js';
import { Port } from '../../domain/value-objects/port.vo.js';
import { GrpcFirewallConntrackMetricsStreamService } from './grpc-firewall-conntrack-metrics-stream.service.js';

@Injectable()
export class GrpcFirewallTcpSessionsQueryService
  implements IFirewallTcpSessionsQueryService, OnModuleInit, OnModuleDestroy
{
  private cachedTcpFlows: ConntrackFlowDto[] = [];
  private subscription?: Subscription;

  constructor(
    private readonly conntrackStream: GrpcFirewallConntrackMetricsStreamService,
  ) {}

  onModuleInit(): void {
    this.subscription = this.conntrackStream.conntrackMetrics$.subscribe(
      (update) => {
        this.cachedTcpFlows = (update.flows ?? []).filter(
          (flow) => flow.original.protocol === 'tcp' && flow.lifecycle === 'active',
        );
      },
    );
  }

  onModuleDestroy(): void {
    this.subscription?.unsubscribe();
  }

  async getTcpSessions(): Promise<TcpTrackedSession[]> {
    return this.cachedTcpFlows.map((flow) => this.toTcpTrackedSession(flow));
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
    );
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
