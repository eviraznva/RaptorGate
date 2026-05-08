import { join } from "node:path";
import { Module } from "@nestjs/common";
import { ConfigService } from "@nestjs/config";
import { ClientsModule, Transport } from "@nestjs/microservices";
import { GrpcFirewallConntrackMetricsStreamService } from "../infrastructure/adapters/grpc-firewall-conntrack-metrics-stream.service.js";
import {
  FIREWALL_METRICS_GRPC_CLIENT_TOKEN,
  GrpcFirewallMetricsStreamService,
} from "../infrastructure/adapters/grpc-firewall-metrics-stream.service.js";
import { MetricsGateway } from "../infrastructure/adapters/metrics.gateway.js";
import type { Env } from "../shared/config/env.validation.js";

@Module({
  imports: [
    ClientsModule.registerAsync([
      {
        name: FIREWALL_METRICS_GRPC_CLIENT_TOKEN,
        useFactory: (configService: ConfigService<Env, true>) => {
          const firewallQuerySocketPath = configService.get(
            "FIREWALL_QUERY_GRPC_SOCKET_PATH",
            { infer: true },
          );

          const resolveGrpcUrl = (path: string): string =>
            path.startsWith("unix://")
              ? path
              : `unix://${join(process.cwd(), path)}`;

          return {
            transport: Transport.GRPC,
            options: {
              package: "raptorgate.services",
              protoPath: join(
                process.cwd(),
                "..",
                "proto",
                "services",
                "metrics_service.proto",
              ),
              loader: {
                includeDirs: [join(process.cwd(), "..", "proto")],
              },
              url: resolveGrpcUrl(firewallQuerySocketPath),
            },
          };
        },
        inject: [ConfigService],
      },
    ]),
  ],
  providers: [
    GrpcFirewallMetricsStreamService,
    GrpcFirewallConntrackMetricsStreamService,
    MetricsGateway,
  ],
})
export class RealtimeMetricsModule {}
