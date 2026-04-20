import { Inject, Injectable, Logger } from "@nestjs/common";
import { DnsInspectionConfig } from "../../domain/entities/dns-inspection-config.entity.js";
import {
  DNS_INSPECTION_REPOSITORY_TOKEN,
  type IDnsInspectionRepository,
} from "../../domain/repositories/dns-inspection.repository.js";
import { IpAddress } from "../../domain/value-objects/ip-address.vo.js";
import { Port } from "../../domain/value-objects/port.vo.js";
import { UpdateDnsInspectionConfigDto } from "../dtos/update-dns-inspection-config.dto.js";
import { UpdateDnsInspectionConfigResponseDto } from "../dtos/update-dns-inspection-config-response.dto.js";
import {
  FIREWALL_DNS_INSPECTION_QUERY_SERVICE_TOKEN,
  type IFirewallDnsInspectionQueryService,
} from "../ports/firewall-dns-inspection-query-service.interface.js";

@Injectable()
export class UpdateDnsInspectionConfigUseCase {
  private readonly logger = new Logger(UpdateDnsInspectionConfigUseCase.name);

  constructor(
    @Inject(DNS_INSPECTION_REPOSITORY_TOKEN)
    private readonly repository: IDnsInspectionRepository,
    @Inject(FIREWALL_DNS_INSPECTION_QUERY_SERVICE_TOKEN)
    private readonly firewallDnsInspectionQueryService: IFirewallDnsInspectionQueryService,
  ) {}

  async execute(
    dto: UpdateDnsInspectionConfigDto,
  ): Promise<UpdateDnsInspectionConfigResponseDto> {
    const dnsInspection = DnsInspectionConfig.create(
      dto.general,
      dto.blocklist,
      dto.dnsTunneling,
      {
        enabled: dto.dnssec.enabled,
        maxLookupsPerPacket: dto.dnssec.maxLookupsPerPacket,
        defaultOnResolverFailure: dto.dnssec.defaultOnResolverFailure,
        resolver: {
          primary: {
            address: IpAddress.create(dto.dnssec.resolver.primary.address),
            port: Port.create(dto.dnssec.resolver.primary.port),
          },
          secondary: {
            address: dto.dnssec.resolver.secondary.address
              ? IpAddress.create(dto.dnssec.resolver.secondary.address)
              : null,
            port: Port.create(dto.dnssec.resolver.secondary.port),
          },
          transport: dto.dnssec.resolver.transport,
          timeoutMs: dto.dnssec.resolver.timeoutMs,
          retries: dto.dnssec.resolver.retries,
        },
        cache: dto.dnssec.cache,
      },
    );

    await this.repository.save(dnsInspection);
    await this.firewallDnsInspectionQueryService.swapDnsInspectionConfig(
      dnsInspection,
    );

    this.logger.log({
      event: "dns_inspection.update.succeeded",
      message: "DNS inspection config updated",
      enabled: dnsInspection.getGeneral().enabled,
      blocklistDomains: dnsInspection.getBlocklist().domains.length,
      dnsTunnelingEnabled: dnsInspection.getDnsTunneling().enabled,
      dnssecEnabled: dnsInspection.getDnssec().enabled,
    });

    return { dnsInspection };
  }
}
