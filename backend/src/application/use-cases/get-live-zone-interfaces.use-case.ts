import { Inject, Injectable } from "@nestjs/common";
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
  ) {}

  async execute(): Promise<GetLiveZoneInterfacesDto> {
    const getLiveZoneInterfaces =
      await this.firewallZoneQueryService.getLiveZoneInterfaces();

    return { zoneInterfaces: getLiveZoneInterfaces };
  }
}
