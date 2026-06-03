import { Inject, Injectable } from "@nestjs/common";
import {
  type IZoneInterfaceRepository,
  ZONE_INTERFACE_REPOSITORY_TOKEN,
} from "src/domain/repositories/zone-interface.repository.js";
import type { GetLiveZoneInterfacesDto } from "../dtos/get-live-zone-interfaces.dto.js";
import {
  FIREWALL_ZONE_QUERY_SERVICE_TOKEN,
  type IFirewallZoneQueryService,
} from "../ports/firewall-zone-query-service.interface.js";

@Injectable()
export class GetLiveZoneInterfacesUseCase {
  constructor(
    @Inject(FIREWALL_ZONE_QUERY_SERVICE_TOKEN)
    private readonly firewallZoneQueryService: IFirewallZoneQueryService,
    @Inject(ZONE_INTERFACE_REPOSITORY_TOKEN)
    private readonly zoneInterfaceRepository: IZoneInterfaceRepository,
  ) {}

  async execute(): Promise<GetLiveZoneInterfacesDto> {
    const firewallZoneInterfaces =
      await this.firewallZoneQueryService.getLiveZoneInterfaces();
    const zoneInterfaces = await this.zoneInterfaceRepository.findAll();

    if (!zoneInterfaces) {
      return { zoneInterfaces: firewallZoneInterfaces };
    }

    return { zoneInterfaces: zoneInterfaces };
  }
}
