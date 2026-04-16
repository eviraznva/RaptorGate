import {
  Inject,
  Injectable,
  OnModuleInit,
  ServiceUnavailableException,
} from "@nestjs/common";
import type { ClientGrpc } from "@nestjs/microservices";
import { firstValueFrom } from "rxjs";
import { IFirewallIpsConfigQueryService } from "src/application/ports/firewall-ips-config-query-service.interface";
import { IpsConfig } from "src/domain/entities/ips-config.entity";
import { IpsSignature } from "src/domain/entities/ips-signature.entity";
import { IpsAction as IpsActionVo } from "src/domain/value-objects/ips-action.vo";
import { IpsAppProtocol as IpsAppProtocolVo } from "src/domain/value-objects/ips-app-protocol.vo";
import { Port } from "src/domain/value-objects/port.vo";
import { RegexPattern } from "src/domain/value-objects/regex-pattern.vo";
import { SignatureCategory } from "src/domain/value-objects/signature-category.vo";
import { SignatureSeverity } from "src/domain/value-objects/signature-severity.vo";
import { Severity } from "../grpc/generated/common/common";
import {
  IpsAction,
  IpsAppProtocol,
} from "../grpc/generated/config/config_models";
import {
  FIREWALL_QUERY_SERVICE_NAME,
  FirewallQueryServiceClient,
} from "../grpc/generated/services/query_service";
import { FIREWALL_QUERY_GRPC_CLIENT_TOKEN } from "./grpc-firewall-dns-inspection-query.service";

@Injectable()
export class GrpcFirewallIpsConfigQueryService
  implements IFirewallIpsConfigQueryService, OnModuleInit
{
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

  async swapIpsConfig(config: IpsConfig): Promise<void> {
    try {
      await firstValueFrom(
        this.firewallQueryClient.swapIpsConfig({
          config: {
            general: config.getGeneral(),
            detection: config.getDetection(),
            signatures: config.getSignatures().map((signature) => {
              return {
                id: signature.getId(),
                name: signature.getName(),
                enabled: signature.getIsActive(),
                category: signature.getCategory().getValue(),
                pattern: signature.getPattern().getValue(),
                severity: Severity[signature.getSeverity().getValue()],
                action: IpsAction[signature.getAction().getValue()],
                appProtocols: signature
                  .getAppProtocols()
                  .map((appProtocol) => IpsAppProtocol[appProtocol.getValue()]),
                srcPorts: signature.getSrcPorts().map((port) => port.getValue),
                dstPorts: signature.getDstPorts().map((port) => port.getValue),
              };
            }),
          },
        }),
      );
    } catch (error) {
      throw new ServiceUnavailableException(error);
    }
  }

  async getIpsConfig(): Promise<IpsConfig> {
    try {
      const response = await firstValueFrom(
        this.firewallQueryClient.getIpsConfig({}),
      );

      if (!response.config) {
        throw new ServiceUnavailableException(
          "Firewall query service returned empty IPS config.",
        );
      }

      return IpsConfig.create(
        response.config.general || {
          enabled: false,
        },
        response.config.detection || {
          enabled: false,
          maxPayloadBytes: 1024,
          maxMatchesPerPacket: 10,
        },
        response.config.signatures.map((signature) => {
          const newSignature = IpsSignature.create(
            signature.id,
            signature.name,
            signature.enabled,
            SignatureCategory.create(signature.category),
            RegexPattern.create(signature.pattern),
            SignatureSeverity.create(Severity[signature.severity]),
            IpsActionVo.create(IpsAction[signature.action]),
            signature.appProtocols.map((appProtocol) =>
              IpsAppProtocolVo.create(IpsAppProtocol[appProtocol]),
            ),
            signature.srcPorts.map((port) => Port.create(port)),
            signature.dstPorts.map((port) => Port.create(port)),
            new Date(),
            new Date(),
          );

          return newSignature;
        }),
      );
    } catch (error) {
      throw new ServiceUnavailableException(error);
    }
  }
}
