import { Module } from '@nestjs/common';
import { JwtService } from '@nestjs/jwt';
import { FIREWALL_TCP_SESSIONS_QUERY_SERVICE_TOKEN } from '../application/ports/firewall-tcp-sessions-query-service.interface.js';
import { TOKEN_SERVICE_TOKEN } from '../application/ports/token-service.interface.js';
import { GetTcpSessionsUseCase } from '../application/use-cases/get-tcp-sessions.use-case.js';
import { GrpcFirewallTcpSessionsQueryService } from '../infrastructure/adapters/grpc-firewall-tcp-sessions-query.service.js';
import { TokenService } from '../infrastructure/adapters/jwt-token.service.js';
import { TcpSessionsController } from '../presentation/controllers/tcp-sessions.controller.js';
import { RealtimeMetricsModule } from './realtime-metrics.module.js';

@Module({
  imports: [RealtimeMetricsModule],
  controllers: [TcpSessionsController],
  providers: [
    GetTcpSessionsUseCase,
    {
      provide: TOKEN_SERVICE_TOKEN,
      useClass: TokenService,
    },
    {
      provide: FIREWALL_TCP_SESSIONS_QUERY_SERVICE_TOKEN,
      useClass: GrpcFirewallTcpSessionsQueryService,
    },
    JwtService,
  ],
})
export class TcpSessionsModule {}
