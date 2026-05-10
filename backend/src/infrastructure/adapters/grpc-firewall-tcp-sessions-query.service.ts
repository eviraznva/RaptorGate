import { Injectable } from '@nestjs/common';
import type { TcpTrackedSession } from '../../domain/entities/tcp-tracked-session.entity.js';
import { GrpcFirewallConntrackMetricsStreamService } from './grpc-firewall-conntrack-metrics-stream.service.js';
import { TcpSessionsConntrackMapper } from './tcp-sessions-conntrack.mapper.js';

@Injectable()
export class GrpcFirewallTcpSessionsQueryService {
  constructor(
    private readonly conntrackStream: GrpcFirewallConntrackMetricsStreamService,
  ) {}

  async getTcpSessions(): Promise<TcpTrackedSession[]> {
    const update = await this.conntrackStream.getConntrackMetricsSnapshot();

    return TcpSessionsConntrackMapper.toTcpTrackedSessions(update);
  }
}
