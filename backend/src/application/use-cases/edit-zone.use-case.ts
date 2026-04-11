import { Inject, Injectable } from '@nestjs/common';
import { AccessTokenIsInvalidException } from '../../domain/exceptions/acces-token-is-invalid.exception.js';
import { AtLeastOneFieldRequiredException } from '../../domain/exceptions/at-least-one-field-required.exception.js';
import { EntityNotFoundException } from '../../domain/exceptions/entity-not-found-exception.js';
import {
  type IZoneRepository,
  ZONE_REPOSITORY_TOKEN,
} from '../../domain/repositories/zone.repository.js';
import type { EditZoneDto } from '../dtos/edit-zone.dto.js';
import type { EditZoneResponseDto } from '../dtos/edit-zone-response.dto.js';
import type { ITokenService } from '../ports/token-service.interface.js';
import { TOKEN_SERVICE_TOKEN } from '../ports/token-service.interface.js';

@Injectable()
export class EditZoneUseCase {
  constructor(
    @Inject(ZONE_REPOSITORY_TOKEN)
    private readonly zoneRepository: IZoneRepository,
    @Inject(TOKEN_SERVICE_TOKEN) private readonly tokenService: ITokenService,
  ) {}

  async execute(dto: EditZoneDto): Promise<EditZoneResponseDto> {
    const isAllUndefined = Object.values(dto).every(
      (value) => value === undefined,
    );

    if (isAllUndefined) throw new AtLeastOneFieldRequiredException();

    const claims = this.tokenService.decodeAccessToken(dto.accessToken);
    if (!claims) throw new AccessTokenIsInvalidException();

    const zone = await this.zoneRepository.findById(dto.id);
    if (!zone) throw new EntityNotFoundException('zone', dto.id);

    if (dto.name !== undefined) zone.setName(dto.name);
    if (dto.description !== undefined) zone.setDescription(dto.description);
    if (dto.isActive !== undefined) zone.setIsActive(dto.isActive);

    await this.zoneRepository.save(zone, zone.getCreatedBy());
    return { zone };
  }
}
