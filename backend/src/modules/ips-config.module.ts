import { Module } from "@nestjs/common";
import { ConfigService } from "@nestjs/config";
import { ClientsModule, Transport } from "@nestjs/microservices";
import { join } from "path";
import { FIREWALL_IPS_CONFIG_QUERY_SERVICE_TOKEN } from "src/application/ports/firewall-ips-config-query-service.interface";
import { GetIpsConfigurationUseCase } from "src/application/use-cases/get-ips-configuration.use-case";
import { UpdateIpsConfigUseCase } from "src/application/use-cases/update-ips-config.use-case";
import { IPS_CONFIG_REPOSITORY_TOKEN } from "src/domain/repositories/ips-config.repository";
import { FIREWALL_QUERY_GRPC_CLIENT_TOKEN } from "src/infrastructure/adapters/grpc-firewall-dns-inspection-query.service";
import { GrpcFirewallIpsConfigQueryService } from "src/infrastructure/adapters/grpc-firewall-ips-config-query.service";
import { Mutex } from "src/infrastructure/persistence/json/file-mutex";
import { FileStore } from "src/infrastructure/persistence/json/file-store";
import { JsonIpsConfigRepository } from "src/infrastructure/persistence/repositories/json-ips-config.repository";
import { IpsConfigController } from "src/presentation/controllers/ips-config.controller";
import { Env } from "src/shared/config/env.validation";

@Module({
  imports: [
    ClientsModule.registerAsync([
      {
        name: FIREWALL_QUERY_GRPC_CLIENT_TOKEN,
        useFactory: (configService: ConfigService<Env, true>) => {
          const backendSocketPath = configService.get("GRPC_SOCKET_PATH", {
            infer: true,
          });

          const firewallQuerySocketPath = configService.get(
            "FIREWALL_QUERY_GRPC_SOCKET_PATH",
            {
              infer: true,
            },
          );

          const resolveGrpcUrl = (path: string): string =>
            path.startsWith("unix://")
              ? path
              : `unix://${join(process.cwd(), path)}`;

          const backendGrpcUrl = resolveGrpcUrl(backendSocketPath);
          const firewallQueryGrpcUrl = resolveGrpcUrl(firewallQuerySocketPath);

          if (backendGrpcUrl === firewallQueryGrpcUrl) {
            throw new Error(
              "FIREWALL_QUERY_GRPC_SOCKET_PATH must point to firewall query service and cannot equal GRPC_SOCKET_PATH.",
            );
          }

          return {
            transport: Transport.GRPC,
            options: {
              package: "raptorgate.services",
              protoPath: join(
                process.cwd(),
                "..",
                "proto",
                "services",
                "query_service.proto",
              ),
              loader: {
                includeDirs: [join(process.cwd(), "..", "proto")],
              },
              url: firewallQueryGrpcUrl,
            },
          };
        },
        inject: [ConfigService],
      },
    ]),
  ],
  controllers: [IpsConfigController],
  providers: [
    GetIpsConfigurationUseCase,
    UpdateIpsConfigUseCase,
    FileStore,
    Mutex,
    {
      provide: IPS_CONFIG_REPOSITORY_TOKEN,
      useClass: JsonIpsConfigRepository,
    },
    {
      provide: FIREWALL_IPS_CONFIG_QUERY_SERVICE_TOKEN,
      useClass: GrpcFirewallIpsConfigQueryService,
    },
  ],
})
export class IpsConfigModule {}
