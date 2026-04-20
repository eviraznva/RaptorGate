import { join } from "node:path";
import { Module } from "@nestjs/common";
import { ConfigService } from "@nestjs/config";
import { ClientsModule, Transport } from "@nestjs/microservices";
import { FIREWALL_DNS_INSPECTION_QUERY_SERVICE_TOKEN } from "../application/ports/firewall-dns-inspection-query-service.interface.js";
import { GetDnsInspectionConfigUseCase } from "../application/use-cases/get-dns-inspection-config.use-case.js";
import { UpdateDnsInspectionConfigUseCase } from "../application/use-cases/update-dns-inspection-config.use-case.js";
import { DNS_INSPECTION_REPOSITORY_TOKEN } from "../domain/repositories/dns-inspection.repository.js";
import {
  FIREWALL_QUERY_GRPC_CLIENT_TOKEN,
  GrpcFirewallDnsInspectionQueryService,
} from "../infrastructure/adapters/grpc-firewall-dns-inspection-query.service.js";
import { Mutex } from "../infrastructure/persistence/json/file-mutex.js";
import { FileStore } from "../infrastructure/persistence/json/file-store.js";
import { JsonDnsInspectionRepository } from "../infrastructure/persistence/repositories/json-dns-inspection.repository.js";
import { DnsInspectionController } from "../presentation/controllers/dns-inspection.controller.js";
import type { Env } from "../shared/config/env.validation.js";

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
  controllers: [DnsInspectionController],
  providers: [
    GetDnsInspectionConfigUseCase,
    UpdateDnsInspectionConfigUseCase,
    FileStore,
    Mutex,
    {
      provide: DNS_INSPECTION_REPOSITORY_TOKEN,
      useClass: JsonDnsInspectionRepository,
    },
    {
      provide: FIREWALL_DNS_INSPECTION_QUERY_SERVICE_TOKEN,
      useClass: GrpcFirewallDnsInspectionQueryService,
    },
  ],
})
export class DnsInspectionModule {}
