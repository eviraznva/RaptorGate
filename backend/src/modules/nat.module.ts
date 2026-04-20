import { join } from 'node:path';
import { Module } from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import { JwtService } from '@nestjs/jwt';
import { ClientsModule, Transport } from '@nestjs/microservices';
import { FIREWALL_NAT_CONFIG_QUERY_SERVICE_TOKEN } from '../application/ports/firewall-nat-config-query-service.interface.js';
import { TOKEN_SERVICE_TOKEN } from '../application/ports/token-service.interface.js';
import { CreateNatRuleUseCase } from '../application/use-cases/create-nat-rule.use-case.js';
import { DeleteNatRuleUseCase } from '../application/use-cases/delete-nat-rule.use-case.js';
import { EditNatRuleUseCase } from '../application/use-cases/edit-nat-rule.use-case.js';
import { GetAllNatRulesUseCase } from '../application/use-cases/get-all-nat-rules.use-case.js';
import { NAT_RULES_REPOSITORY_TOKEN } from '../domain/repositories/nat-rules.repository.js';
import { FIREWALL_QUERY_GRPC_CLIENT_TOKEN } from '../infrastructure/adapters/grpc-firewall-dns-inspection-query.service.js';
import { GrpcFirewallNatConfigQueryService } from '../infrastructure/adapters/grpc-firewall-nat-config-query.service.js';
import { TokenService } from '../infrastructure/adapters/jwt-token.service.js';
import { Mutex } from '../infrastructure/persistence/json/file-mutex.js';
import { FileStore } from '../infrastructure/persistence/json/file-store.js';
import { JsonNatRuleRepository } from '../infrastructure/persistence/repositories/json-nat-rule.repository.js';
import { NatRuleController } from '../presentation/controllers/nat-rule.controller.js';
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
  controllers: [NatRuleController],
  providers: [
    CreateNatRuleUseCase,
    GetAllNatRulesUseCase,
    EditNatRuleUseCase,
    DeleteNatRuleUseCase,
    Mutex,
    FileStore,
    {
      provide: NAT_RULES_REPOSITORY_TOKEN,
      useClass: JsonNatRuleRepository,
    },
    {
      provide: TOKEN_SERVICE_TOKEN,
      useClass: TokenService,
    },
    JwtService,
    {
      provide: FIREWALL_NAT_CONFIG_QUERY_SERVICE_TOKEN,
      useClass: GrpcFirewallNatConfigQueryService,
    },
  ],
})
export class NatModule {}
