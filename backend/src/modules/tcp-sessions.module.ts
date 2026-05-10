import { Module } from '@nestjs/common';
import { GrpcFirewallTcpSessionsQueryService } from '../infrastructure/adapters/grpc-firewall-tcp-sessions-query.service.js';
import { SessionsGateway } from '../infrastructure/adapters/sessions.gateway.js';
import { AuthModule } from './auth.module.js';
import { RealtimeMetricsModule } from './realtime-metrics.module.js';

@Module({
  imports: [RealtimeMetricsModule, AuthModule],
  providers: [GrpcFirewallTcpSessionsQueryService, SessionsGateway],
})
export class TcpSessionsModule {}
