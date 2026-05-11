import { join } from 'node:path';
import { Module } from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import { JwtService } from '@nestjs/jwt';
import { ClientsModule, Transport } from '@nestjs/microservices';
import { FIREWALL_ZONE_QUERY_SERVICE_TOKEN } from '../application/ports/firewall-zone-query-service.interface.js';
import { TOKEN_SERVICE_TOKEN } from '../application/ports/token-service.interface.js';
import { CreateZoneUseCase } from '../application/use-cases/create-zone.use-case.js';
import { DeleteZoneUseCase } from '../application/use-cases/delete-zone.use-case.js';
import { EditZoneInterfaceUseCase } from '../application/use-cases/edit-zone-interface.use-case.js';
import { EditZoneUseCase } from '../application/use-cases/edit-zone.use-case.js';
import { GetAllZonesUseCase } from '../application/use-cases/get-all-zones.use-case.js';
import { GetLiveZoneInterfacesUseCase } from '../application/use-cases/get-live-zone-interfaces.use-case.js';
import { ZONE_REPOSITORY_TOKEN } from '../domain/repositories/zone.repository.js';
import { ZONE_INTERFACE_REPOSITORY_TOKEN } from '../domain/repositories/zone-interface.repository.js';
import { ZONE_PAIR_REPOSITORY_TOKEN } from '../domain/repositories/zone-pair.repository.js';
import { FIREWALL_QUERY_GRPC_CLIENT_TOKEN } from '../infrastructure/adapters/grpc-firewall-dns-inspection-query.service.js';
import { GrpcFirewallZoneQueryService } from '../infrastructure/adapters/grpc-firewall-zone-query.service.js';
import { TokenService } from '../infrastructure/adapters/jwt-token.service.js';
import { Mutex } from '../infrastructure/persistence/json/file-mutex.js';
import { FileStore } from '../infrastructure/persistence/json/file-store.js';
import { JsonZoneInterfaceRepository } from '../infrastructure/persistence/repositories/json-zone-interface.repository.js';
import { JsonZoneRepository } from '../infrastructure/persistence/repositories/json-zone.repository.js';
import { JsonZonePairRepository } from '../infrastructure/persistence/repositories/json-zone-pair.repository.js';
import { ZoneController } from '../presentation/controllers/zone.controller.js';
import { ZoneInterfaceController } from '../presentation/controllers/zone-interface.controller.js';
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
  controllers: [ZoneController, ZoneInterfaceController],
  providers: [
    CreateZoneUseCase,
    GetAllZonesUseCase,
    GetLiveZoneInterfacesUseCase,
    EditZoneInterfaceUseCase,
    EditZoneUseCase,
    DeleteZoneUseCase,
    FileStore,
    Mutex,
    {
      provide: ZONE_REPOSITORY_TOKEN,
      useClass: JsonZoneRepository,
    },
    {
      provide: ZONE_PAIR_REPOSITORY_TOKEN,
      useClass: JsonZonePairRepository,
    },
    {
      provide: ZONE_INTERFACE_REPOSITORY_TOKEN,
      useClass: JsonZoneInterfaceRepository,
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
export class ZoneModule {}
