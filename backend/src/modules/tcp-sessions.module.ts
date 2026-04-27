import { join } from 'node:path';
import { Module } from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import { JwtService } from '@nestjs/jwt';
import { ClientsModule, Transport } from '@nestjs/microservices';
import { FIREWALL_TCP_SESSIONS_QUERY_SERVICE_TOKEN } from '../application/ports/firewall-tcp-sessions-query-service.interface.js';
import { TOKEN_SERVICE_TOKEN } from '../application/ports/token-service.interface.js';
import { GetTcpSessionsUseCase } from '../application/use-cases/get-tcp-sessions.use-case.js';
import {
  FIREWALL_TCP_SESSIONS_GRPC_CLIENT_TOKEN,
  GrpcFirewallTcpSessionsQueryService,
} from '../infrastructure/adapters/grpc-firewall-tcp-sessions-query.service.js';
import { TokenService } from '../infrastructure/adapters/jwt-token.service.js';
import { TcpSessionsController } from '../presentation/controllers/tcp-sessions.controller.js';
import type { Env } from '../shared/config/env.validation.js';

@Module({
  imports: [
    ClientsModule.registerAsync([
      {
        name: FIREWALL_TCP_SESSIONS_GRPC_CLIENT_TOKEN,
        useFactory: (configService: ConfigService<Env, true>) => {
          const firewallQuerySocketPath = configService.get(
            'FIREWALL_QUERY_GRPC_SOCKET_PATH',
            {
              infer: true,
            },
          );

          const resolveGrpcUrl = (path: string): string =>
            path.startsWith('unix://')
              ? path
              : `unix://${join(process.cwd(), path)}`;

          return {
            transport: Transport.GRPC,
            options: {
              package: 'raptorgate.services',
              protoPath: join(
                process.cwd(),
                '..',
                'proto',
                'services',
                'query_service.proto',
              ),
              loader: {
                includeDirs: [join(process.cwd(), '..', 'proto')],
              },
              url: resolveGrpcUrl(firewallQuerySocketPath),
            },
          };
        },
        inject: [ConfigService],
      },
    ]),
  ],
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
