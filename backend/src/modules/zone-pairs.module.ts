import { join } from 'node:path';
import { ConfigService } from '@nestjs/config';
import { ClientsModule, Transport } from '@nestjs/microservices';
import { JsonZonePairRepository } from '../infrastructure/persistence/repositories/json-zone-pair.repository.js';
import { JsonZoneRepository } from '../infrastructure/persistence/repositories/json-zone.repository.js';
import { GetAllZonePairsUseCase } from '../application/use-cases/get-all-zone-pairs.use-case.js';
import { CreateZonePairUseCase } from '../application/use-cases/create-zone-pair.use-case.js';
import { DeleteZonePairUseCase } from '../application/use-cases/delete-zone-pair.use-case.js';
import { FIREWALL_ZONE_QUERY_SERVICE_TOKEN } from '../application/ports/firewall-zone-query-service.interface.js';
import { ZONE_PAIR_REPOSITORY_TOKEN } from '../domain/repositories/zone-pair.repository.js';
import { ZonePairsController } from '../presentation/controllers/zone-pairs.controller.js';
import { EditZonePairUseCase } from '../application/use-cases/edit-zone-pair.use-case.js';
import { TOKEN_SERVICE_TOKEN } from '../application/ports/token-service.interface.js';
import { ZONE_REPOSITORY_TOKEN } from '../domain/repositories/zone.repository.js';
import { FIREWALL_QUERY_GRPC_CLIENT_TOKEN } from '../infrastructure/adapters/grpc-firewall-dns-inspection-query.service.js';
import { GrpcFirewallZoneQueryService } from '../infrastructure/adapters/grpc-firewall-zone-query.service.js';
import { TokenService } from '../infrastructure/adapters/jwt-token.service.js';
import { FileStore } from '../infrastructure/persistence/json/file-store.js';
import { Mutex } from '../infrastructure/persistence/json/file-mutex.js';
import { JwtService } from '@nestjs/jwt';
import { Module } from '@nestjs/common';
import type { Env } from '../shared/config/env.validation.js';

@Module({
  imports: [
    ClientsModule.registerAsync([
      {
        name: FIREWALL_QUERY_GRPC_CLIENT_TOKEN,
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
  controllers: [ZonePairsController],
  providers: [
    CreateZonePairUseCase,
    GetAllZonePairsUseCase,
    EditZonePairUseCase,
    DeleteZonePairUseCase,
    Mutex,
    FileStore,
    {
      provide: ZONE_PAIR_REPOSITORY_TOKEN,
      useClass: JsonZonePairRepository,
    },
    {
      provide: ZONE_REPOSITORY_TOKEN,
      useClass: JsonZoneRepository,
    },
    {
      provide: TOKEN_SERVICE_TOKEN,
      useClass: TokenService,
    },
    {
      provide: FIREWALL_ZONE_QUERY_SERVICE_TOKEN,
      useClass: GrpcFirewallZoneQueryService,
    },
    JwtService,
  ],
})
export class ZonePairsModule {}
