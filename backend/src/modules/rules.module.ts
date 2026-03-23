import {
  GrpcRaptorLangValidationService,
  RAPTOR_LANG_VALIDATION_GRPC_CLIENT_TOKEN,
} from 'src/infrastructure/adapters/grpc-raptor-lang-validation.service';
import { RAPTOR_LANG_VALIDATION_SERVICE_TOKEN } from 'src/application/ports/raptor-lang-validation-service.interface';
import { JsonRuleRepository } from 'src/infrastructure/persistence/repositories/json-rule.repository';
import { GetAllRulesUseCase } from 'src/application/use-cases/get-all-rules.use-case';
import { TOKEN_SERVICE_TOKEN } from 'src/application/ports/token-service.interface';
import { CreateRuleUseCase } from 'src/application/use-cases/create-rule.use-case';
import { DeleteRuleUseCase } from 'src/application/use-cases/delete-rule.use-case';
import { RULES_REPOSITORY_TOKEN } from 'src/domain/repositories/rules-repository';
import { EditRuleUseCase } from 'src/application/use-cases/edit-rule.use-case';
import { RulesController } from 'src/presentation/controllers/rule.controller';
import { TokenService } from 'src/infrastructure/adapters/jwt-token.service';
import { FileStore } from 'src/infrastructure/persistence/json/file-store';
import { Mutex } from 'src/infrastructure/persistence/json/file-mutex';
import { ClientsModule, Transport } from '@nestjs/microservices';
import { Env } from 'src/shared/config/env.validation';
import { ConfigService } from '@nestjs/config';
import { JwtService } from '@nestjs/jwt';
import { Module } from '@nestjs/common';
import { join } from 'node:path';

@Module({
  imports: [
    ClientsModule.registerAsync([
      {
        name: RAPTOR_LANG_VALIDATION_GRPC_CLIENT_TOKEN,
        useFactory: (configService: ConfigService<Env, true>) => {
          const backendSocketPath = configService.get('GRPC_SOCKET_PATH', {
            infer: true,
          });
          const firewallSocketPath = configService.get(
            'FIREWALL_GRPC_SOCKET_PATH',
            {
              infer: true,
            },
          );
          const resolveGrpcUrl = (path: string): string =>
            path.startsWith('unix://')
              ? path
              : `unix://${join(process.cwd(), path)}`;

          const backendGrpcUrl = resolveGrpcUrl(backendSocketPath);
          const firewallGrpcUrl = resolveGrpcUrl(firewallSocketPath);

          if (backendGrpcUrl === firewallGrpcUrl) {
            throw new Error(
              'FIREWALL_GRPC_SOCKET_PATH must point to firewall validation service and cannot equal GRPC_SOCKET_PATH.',
            );
          }

          const grpcUrl = firewallGrpcUrl;

          return {
            transport: Transport.GRPC,
            options: {
              package: 'raptorgate.control',
              protoPath: join(
                process.cwd(),
                '..',
                'proto',
                'control',
                'validation_service.proto',
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
  controllers: [RulesController],
  providers: [
    GetAllRulesUseCase,
    EditRuleUseCase,
    DeleteRuleUseCase,
    CreateRuleUseCase,
    FileStore,
    Mutex,
    {
      provide: TOKEN_SERVICE_TOKEN,
      useClass: TokenService,
    },
    {
      provide: RAPTOR_LANG_VALIDATION_SERVICE_TOKEN,
      useClass: GrpcRaptorLangValidationService,
    },
    {
      provide: RULES_REPOSITORY_TOKEN,
      useClass: JsonRuleRepository,
    },
    JwtService,
  ],
})
export class RulesModule {}
