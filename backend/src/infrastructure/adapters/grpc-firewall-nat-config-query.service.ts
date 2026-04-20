import {
  Inject,
  Injectable,
  Logger,
  OnModuleInit,
  ServiceUnavailableException,
} from "@nestjs/common";
import type { ClientGrpc } from "@nestjs/microservices";
import { firstValueFrom } from "rxjs";
import { IFirewallNatConfigQueryService } from "src/application/ports/firewall-nat-config-query-service.interface";
import { NatRule } from "src/domain/entities/nat-rule.entity";
import { IpAddress } from "src/domain/value-objects/ip-address.vo";
import { NatType } from "src/domain/value-objects/nat-type.vo";
import { Port } from "src/domain/value-objects/port.vo";
import { Priority } from "src/domain/value-objects/priority.vo";
import { NatRuleType } from "../grpc/generated/common/common";
import {
  FIREWALL_QUERY_SERVICE_NAME,
  FirewallQueryServiceClient,
} from "../grpc/generated/services/query_service";
import { FIREWALL_QUERY_GRPC_CLIENT_TOKEN } from "./grpc-firewall-dns-inspection-query.service";

const NAT_TYPE_TO_PROTO: Record<string, NatRuleType> = {
  SNAT: NatRuleType.NAT_RULE_TYPE_SNAT,
  DNAT: NatRuleType.NAT_RULE_TYPE_DNAT,
  PAT: NatRuleType.NAT_RULE_TYPE_PAT,
};

const PROTO_TO_NAT_TYPE: Record<number, string> = {
  [NatRuleType.NAT_RULE_TYPE_SNAT]: "SNAT",
  [NatRuleType.NAT_RULE_TYPE_DNAT]: "DNAT",
  [NatRuleType.NAT_RULE_TYPE_PAT]: "PAT",
};

@Injectable()
export class GrpcFirewallNatConfigQueryService
  implements IFirewallNatConfigQueryService, OnModuleInit
{
  private readonly logger = new Logger(GrpcFirewallNatConfigQueryService.name);
  private firewallQueryClient: FirewallQueryServiceClient;

  constructor(
    @Inject(FIREWALL_QUERY_GRPC_CLIENT_TOKEN)
    private readonly grpcClient: ClientGrpc,
  ) {}

  onModuleInit() {
    this.firewallQueryClient =
      this.grpcClient.getService<FirewallQueryServiceClient>(
        FIREWALL_QUERY_SERVICE_NAME,
      );
  }

  async swapNatConfig(rules: NatRule[]): Promise<void> {
    try {
      this.logger.log({
        event: "firewall.nat.swap.started",
        message: "swapping NAT config on firewall",
        rules: rules.length,
      });

      await firstValueFrom(
        this.firewallQueryClient.swapNatConfig({
          config: {
            items: rules.map((rule) => ({
              id: rule.getId(),
              type: NAT_TYPE_TO_PROTO[rule.getType().getValue()],
              srcIp: rule.getSourceIp()?.getValue ?? "",
              dstIp: rule.getDestinationIp()?.getValue ?? "",
              srcPort: rule.getSourcePort()?.getValue ?? undefined,
              dstPort: rule.getDestinationPort()?.getValue ?? undefined,
              translatedIp: rule.getTranslatedIp()?.getValue ?? "",
              translatedPort: rule.getTranslatedPort()?.getValue ?? undefined,
              priority: rule.getPriority().getValue(),
            })),
          },
        }),
      );

      this.logger.log({
        event: "firewall.nat.swap.succeeded",
        message: "NAT config swapped on firewall",
        rules: rules.length,
      });
    } catch (error) {
      const reason =
        error instanceof Error ? error.message : "Unknown gRPC error";

      this.logger.error(
        {
          event: "firewall.nat.swap.failed",
          message: "failed to swap NAT config on firewall",
          error: reason,
        },
        error instanceof Error ? error.stack : undefined,
      );

      throw new ServiceUnavailableException(
        `Firewall query service failed to swap NAT config. ${reason}`,
      );
    }
  }

  async getNatConfig(): Promise<NatRule[]> {
    try {
      this.logger.log({
        event: "firewall.nat.get.started",
        message: "loading NAT config from firewall",
      });

      const response = await firstValueFrom(
        this.firewallQueryClient.getNatConfig({}),
      );

      if (!response.config) {
        throw new ServiceUnavailableException(
          "Firewall query service returned empty NAT config.",
        );
      }

      const rules = response.config.items.map((item) => {
        const typeName = PROTO_TO_NAT_TYPE[item.type];
        if (!typeName) {
          throw new ServiceUnavailableException(
            `Unknown NAT rule type: ${item.type}`,
          );
        }

        return NatRule.create(
          item.id,
          NatType.create(typeName),
          true,
          item.srcIp ? IpAddress.create(item.srcIp) : null,
          item.dstIp ? IpAddress.create(item.dstIp) : null,
          item.srcPort != null ? Port.create(item.srcPort) : null,
          item.dstPort != null ? Port.create(item.dstPort) : null,
          item.translatedIp ? IpAddress.create(item.translatedIp) : null,
          item.translatedPort != null
            ? Port.create(item.translatedPort)
            : null,
          Priority.create(item.priority),
          new Date(),
          new Date(),
        );
      });

      this.logger.log({
        event: "firewall.nat.get.succeeded",
        message: "loaded NAT config from firewall",
        rules: rules.length,
      });

      return rules;
    } catch (error) {
      const reason =
        error instanceof Error ? error.message : "Unknown gRPC error";

      this.logger.error(
        {
          event: "firewall.nat.get.failed",
          message: "failed to load NAT config from firewall",
          error: reason,
        },
        error instanceof Error ? error.stack : undefined,
      );

      throw new ServiceUnavailableException(
        `Firewall query service failed to get NAT config. ${reason}`,
      );
    }
  }
}
