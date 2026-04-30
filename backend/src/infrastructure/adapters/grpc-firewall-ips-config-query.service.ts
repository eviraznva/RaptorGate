import {
  Inject,
  Injectable,
  Logger,
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
import { IpsMatchType as IpsMatchTypeVo } from "src/domain/value-objects/ips-match-type.vo";
import { IpsPatternEncoding as IpsPatternEncodingVo } from "src/domain/value-objects/ips-pattern-encoding.vo";
import { Port } from "src/domain/value-objects/port.vo";
import { RegexPattern } from "src/domain/value-objects/regex-pattern.vo";
import { SignatureCategory } from "src/domain/value-objects/signature-category.vo";
import { SignatureSeverity } from "src/domain/value-objects/signature-severity.vo";
import { Severity } from "../grpc/generated/common/common";
import {
  IpsAction,
  IpsAppProtocol,
  IpsMatchType as ProtoIpsMatchType,
  IpsPatternEncoding as ProtoIpsPatternEncoding,
} from "../grpc/generated/config/config_models";
import {
  FIREWALL_QUERY_SERVICE_NAME,
  FirewallQueryServiceClient,
} from "../grpc/generated/services/query_service";
import { FIREWALL_QUERY_GRPC_CLIENT_TOKEN } from "./grpc-firewall-dns-inspection-query.service";

function mapMatchTypeFromProto(value: ProtoIpsMatchType): string {
  switch (value) {
    case ProtoIpsMatchType.IPS_MATCH_TYPE_LITERAL:
      return "IPS_MATCH_TYPE_LITERAL";
    case ProtoIpsMatchType.IPS_MATCH_TYPE_REGEX:
    case ProtoIpsMatchType.IPS_MATCH_TYPE_UNSPECIFIED:
    default:
      return "IPS_MATCH_TYPE_REGEX";
  }
}

function mapPatternEncodingFromProto(value: ProtoIpsPatternEncoding): string {
  switch (value) {
    case ProtoIpsPatternEncoding.IPS_PATTERN_ENCODING_HEX:
      return "IPS_PATTERN_ENCODING_HEX";
    case ProtoIpsPatternEncoding.IPS_PATTERN_ENCODING_TEXT:
    case ProtoIpsPatternEncoding.IPS_PATTERN_ENCODING_UNSPECIFIED:
    default:
      return "IPS_PATTERN_ENCODING_TEXT";
  }
}

@Injectable()
export class GrpcFirewallIpsConfigQueryService
  implements IFirewallIpsConfigQueryService, OnModuleInit
{
  private readonly logger = new Logger(GrpcFirewallIpsConfigQueryService.name);
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
      this.logger.log({
        event: "firewall.ips.swap.started",
        message: "swapping IPS config on firewall",
        enabled: config.getGeneral().enabled,
        detectionEnabled: config.getDetection().enabled,
        signatures: config.getSignatures().length,
      });

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
                matchType:
                  ProtoIpsMatchType[signature.getMatchType().getValue()],
                patternEncoding:
                  ProtoIpsPatternEncoding[
                    signature.getPatternEncoding().getValue()
                  ],
                caseInsensitive: signature.getCaseInsensitive(),
              };
            }),
          },
        }),
      );

      this.logger.log({
        event: "firewall.ips.swap.succeeded",
        message: "IPS config swapped on firewall",
        enabled: config.getGeneral().enabled,
        signatures: config.getSignatures().length,
      });
    } catch (error) {
      const reason =
        error instanceof Error ? error.message : "Unknown gRPC error";

      this.logger.error(
        {
          event: "firewall.ips.swap.failed",
          message: "failed to swap IPS config on firewall",
          error: reason,
        },
        error instanceof Error ? error.stack : undefined,
      );

      throw new ServiceUnavailableException(
        `Firewall query service failed to swap IPS config. ${reason}`,
      );
    }
  }

  async getIpsConfig(): Promise<IpsConfig> {
    try {
      this.logger.log({
        event: "firewall.ips.get.started",
        message: "loading IPS config from firewall",
      });

      const response = await firstValueFrom(
        this.firewallQueryClient.getIpsConfig({}),
      );

      if (!response.config) {
        throw new ServiceUnavailableException(
          "Firewall query service returned empty IPS config.",
        );
      }

      const config = IpsConfig.create(
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
            IpsMatchTypeVo.create(mapMatchTypeFromProto(signature.matchType)),
            IpsPatternEncodingVo.create(
              mapPatternEncodingFromProto(signature.patternEncoding),
            ),
            signature.caseInsensitive,
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

      this.logger.log({
        event: "firewall.ips.get.succeeded",
        message: "loaded IPS config from firewall",
        enabled: config.getGeneral().enabled,
        signatures: config.getSignatures().length,
      });

      return config;
    } catch (error) {
      const reason =
        error instanceof Error ? error.message : "Unknown gRPC error";

      this.logger.error(
        {
          event: "firewall.ips.get.failed",
          message: "failed to load IPS config from firewall",
          error: reason,
        },
        error instanceof Error ? error.stack : undefined,
      );

      throw new ServiceUnavailableException(
        `Firewall query service failed to get IPS config. ${reason}`,
      );
    }
  }
}
