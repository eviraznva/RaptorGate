import { Inject, Injectable } from "@nestjs/common";
import { EntityNotFoundException } from "src/domain/exceptions/entity-not-found-exception.js";
import type { IZoneRepository } from "../../domain/repositories/zone.repository.js";
import { ZONE_REPOSITORY_TOKEN } from "../../domain/repositories/zone.repository.js";
import type { GetAllZonesDto } from "../dtos/get-all-zones.dto.js";
import { GetZonesQueryDto } from "../dtos/get-zones.dto.js";

@Injectable()
export class GetAllZonesUseCase {
  constructor(
    @Inject(ZONE_REPOSITORY_TOKEN)
    private readonly zoneRepository: IZoneRepository,
  ) {}

  async execute(dto: GetZonesQueryDto): Promise<GetAllZonesDto> {
    const zones = await this.zoneRepository.findAll();
    if (!zones) throw new EntityNotFoundException("zones", "all");
    let result = zones;

    if (dto.isActive !== undefined)
      result = result.filter((zone) => zone.getIsActive() === dto.isActive);

    if (dto.page !== undefined && dto.limit !== undefined)
      result = result.slice((dto.page - 1) * dto.limit, dto.page * dto.limit);

    return { zones };
  }
}
