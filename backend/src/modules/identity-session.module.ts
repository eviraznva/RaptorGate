import { join } from 'node:path';
import { Module } from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import { ClientsModule, Transport } from '@nestjs/microservices';
import { IDENTITY_SESSION_SYNC_SERVICE_TOKEN } from '../application/ports/identity-session-sync-service.interface.js';
import {
  GrpcIdentitySessionSyncService,
  IDENTITY_SESSION_SYNC_GRPC_CLIENT_TOKEN,
} from '../infrastructure/adapters/grpc-identity-session-sync.service.js';
import { Env } from '../shared/config/env.validation.js';

// Modul klienta gRPC dla IdentitySessionService hostowanego przez firewall.
// Osobny kanal od PushActiveConfigSnapshot (ADR 0002), ale fizycznie ten sam
// UDS co FirewallQueryService (FIREWALL_QUERY_GRPC_SOCKET_PATH).
// TODO(Issue 3): AuthModule/session lifecycle bedzie uzywal IDENTITY_SESSION_SYNC_SERVICE_TOKEN.
@Module({
  imports: [
    ClientsModule.registerAsync([
      {
        name: IDENTITY_SESSION_SYNC_GRPC_CLIENT_TOKEN,
        useFactory: (configService: ConfigService<Env, true>) => {
          const firewallSocketPath = configService.get(
            'FIREWALL_QUERY_GRPC_SOCKET_PATH',
            { infer: true },
          );

          const grpcUrl = firewallSocketPath.startsWith('unix://')
            ? firewallSocketPath
            : `unix://${join(process.cwd(), firewallSocketPath)}`;

          return {
            transport: Transport.GRPC,
            options: {
              package: 'raptorgate.services',
              protoPath: join(
                process.cwd(),
                '..',
                'proto',
                'services',
                'identity_session_service.proto',
              ),
              loader: {
                includeDirs: [join(process.cwd(), '..', 'proto')],
              },
              url: grpcUrl,
            },
          };
        },
        inject: [ConfigService],
      },
    ]),
  ],
  providers: [
    GrpcIdentitySessionSyncService,
    {
      provide: IDENTITY_SESSION_SYNC_SERVICE_TOKEN,
      useExisting: GrpcIdentitySessionSyncService,
    },
  ],
  exports: [IDENTITY_SESSION_SYNC_SERVICE_TOKEN],
})
export class IdentitySessionModule {}
