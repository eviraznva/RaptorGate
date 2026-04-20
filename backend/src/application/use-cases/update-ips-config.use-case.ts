import { Inject, Injectable, Logger } from "@nestjs/common";
import { IpsConfig } from "src/domain/entities/ips-config.entity";
import { IpsSignature } from "src/domain/entities/ips-signature.entity";
import {
  type IIpsConfigRepository,
  IPS_CONFIG_REPOSITORY_TOKEN,
} from "src/domain/repositories/ips-config.repository";
import { IpsAction } from "src/domain/value-objects/ips-action.vo";
import { IpsAppProtocol } from "src/domain/value-objects/ips-app-protocol.vo";
import { Port } from "src/domain/value-objects/port.vo";
import { RegexPattern } from "src/domain/value-objects/regex-pattern.vo";
import { SignatureCategory } from "src/domain/value-objects/signature-category.vo";
import { SignatureSeverity } from "src/domain/value-objects/signature-severity.vo";
import { IpsConfigDto } from "../dtos/update-ips-config.dto";
import { UpdateIpsConfigResponseDto } from "../dtos/update-ips-config-response.dto";
import {
  FIREWALL_IPS_CONFIG_QUERY_SERVICE_TOKEN,
  type IFirewallIpsConfigQueryService,
} from "../ports/firewall-ips-config-query-service.interface";

@Injectable()
export class UpdateIpsConfigUseCase {
  private readonly logger = new Logger(UpdateIpsConfigUseCase.name);

  constructor(
    @Inject(IPS_CONFIG_REPOSITORY_TOKEN)
    private readonly ipsConfigRepository: IIpsConfigRepository,
    @Inject(FIREWALL_IPS_CONFIG_QUERY_SERVICE_TOKEN)
    private readonly firewallIpsConfigQueryService: IFirewallIpsConfigQueryService,
  ) {}

  async execute(dto: IpsConfigDto): Promise<UpdateIpsConfigResponseDto> {
    const newIpsConfig = IpsConfig.create(
      dto.general,
      dto.detection,
      dto.signatures.map((signature) =>
        IpsSignature.create(
          crypto.randomUUID(),
          signature.name,
          signature.enabled,
          SignatureCategory.create(signature.category),
          RegexPattern.create(signature.pattern),
          SignatureSeverity.create(signature.severity),
          IpsAction.create(signature.action),
          signature.appProtocols.map((appProtocol) =>
            IpsAppProtocol.create(appProtocol),
          ),
          signature.srcPorts.map((port) => Port.create(port)),
          signature.dstPorts.map((port) => Port.create(port)),
          new Date(),
          new Date(),
        ),
      ),
    );

    await this.ipsConfigRepository.save(newIpsConfig);

    await this.firewallIpsConfigQueryService.swapIpsConfig(newIpsConfig);

    this.logger.log({
      event: "ips.update.succeeded",
      message: "IPS config updated",
      enabled: newIpsConfig.getGeneral().enabled,
      detectionEnabled: newIpsConfig.getDetection().enabled,
      signatures: newIpsConfig.getSignatures().length,
    });

    return { ipsConfig: newIpsConfig };
  }
}
