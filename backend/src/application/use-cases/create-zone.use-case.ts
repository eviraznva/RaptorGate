import { AccessTokenIsInvalidException } from '../../domain/exceptions/acces-token-is-invalid.exception.js';
import { EntityAlreadyExistsException } from '../../domain/exceptions/entity-already-exists-exception.js';
import { ZONE_REPOSITORY_TOKEN } from '../../domain/repositories/zone.repository.js';
import type { IZoneRepository } from '../../domain/repositories/zone.repository.js';
import { TOKEN_SERVICE_TOKEN } from '../ports/token-service.interface.js';
import { CreateZoneResponseDto } from '../dtos/create-zone-response.dto.js';
import type { ITokenService } from '../ports/token-service.interface.js';
import { Zone } from '../../domain/entities/zone.entity.js';
import { CreateZoneDto } from '../dtos/create-zone.dto.js';
import { Inject, Injectable, Logger } from '@nestjs/common';

@Injectable()
export class CreateZoneUseCase {
  private readonly logger = new Logger(CreateZoneUseCase.name);

  constructor(
    @Inject(ZONE_REPOSITORY_TOKEN)
    private readonly zoneRepository: IZoneRepository,
    @Inject(TOKEN_SERVICE_TOKEN) private readonly tokenService: ITokenService,
  ) {}

  async execute(dto: CreateZoneDto): Promise<CreateZoneResponseDto> {
    const findExisting = await this.zoneRepository.findByName(dto.name);
    if (findExisting)
      throw new EntityAlreadyExistsException('zone', 'name', dto.name);

    const claims = this.tokenService.decodeAccessToken(dto.accessToken);
    if (!claims) throw new AccessTokenIsInvalidException();

    const newZone = Zone.create(
      crypto.randomUUID(),
      dto.name,
      dto.description || null,
      dto.isActive,
      new Date(),
      claims.sub,
    );

    await this.zoneRepository.save(newZone, claims.sub);

    this.logger.log({
      event: 'zone.create.succeeded',
      message: 'zone created',
      actorId: claims.sub,
      zoneId: newZone.getId(),
      zoneName: newZone.getName(),
      isActive: newZone.getIsActive(),
    });

    return { zone: newZone };
  }
}
