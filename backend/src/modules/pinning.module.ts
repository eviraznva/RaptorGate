import { join } from 'node:path';
import { Module } from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import { JwtService } from '@nestjs/jwt';
import { ClientsModule, Transport } from '@nestjs/microservices';
import { PINNING_OBSERVABILITY_SERVICE_TOKEN } from '../application/ports/pinning-observability-service.interface.js';
import { TOKEN_SERVICE_TOKEN } from '../application/ports/token-service.interface.js';
import {
  GrpcPinningObservabilityService,
  PINNING_OBSERVABILITY_GRPC_CLIENT_TOKEN,
} from '../infrastructure/adapters/grpc-pinning-observability.service.js';
import { TokenService } from '../infrastructure/adapters/jwt-token.service.js';
import { PinningController } from '../presentation/controllers/pinning.controller.js';
import { Env } from '../shared/config/env.validation.js';

@Module({
  imports: [
    ClientsModule.registerAsync([
      {
        name: PINNING_OBSERVABILITY_GRPC_CLIENT_TOKEN,
        useFactory: (configService: ConfigService<Env, true>) => {
          const querySocketPath = configService.get(
            'FIREWALL_QUERY_SOCKET_PATH',
            { infer: true },
          );

          const grpcUrl = querySocketPath.startsWith('unix://')
            ? querySocketPath
            : `unix://${join(process.cwd(), querySocketPath)}`;

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
              url: grpcUrl,
            },
          };
        },
        inject: [ConfigService],
      },
    ]),
  ],
  controllers: [PinningController],
  providers: [
    {
      provide: TOKEN_SERVICE_TOKEN,
      useClass: TokenService,
    },
    {
      provide: PINNING_OBSERVABILITY_SERVICE_TOKEN,
      useClass: GrpcPinningObservabilityService,
    },
    JwtService,
  ],
})
export class PinningModule {}
