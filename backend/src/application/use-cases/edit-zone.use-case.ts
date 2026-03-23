import {
  ZONE_REPOSITORY_TOKEN,
  type IZoneRepository,
} from 'src/domain/repositories/zone.repository';
import { AtLeastOneFieldRequiredException } from 'src/domain/exceptions/at-least-one-field-required.exception';
import { AccessTokenIsInvalidException } from 'src/domain/exceptions/acces-token-is-invalid.exception';
import { TOKEN_SERVICE_TOKEN } from '../ports/token-service.interface';
import type { ITokenService } from '../ports/token-service.interface';
import { EditZoneResponseDto } from '../dtos/edit-zone-response.dto';
import { EditZoneDto } from '../dtos/edit-zone.dto';
import { Inject } from '@nestjs/common';
import { EntityNotFoundException } from 'src/domain/exceptions/entity-not-found-exception';

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
