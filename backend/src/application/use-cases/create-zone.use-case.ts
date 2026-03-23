import { AccessTokenIsInvalidException } from 'src/domain/exceptions/acces-token-is-invalid.exception';
import { EntityAlreadyExistsException } from 'src/domain/exceptions/entity-already-exists-exception';
import { ZONE_REPOSITORY_TOKEN } from 'src/domain/repositories/zone.repository';
import type { IZoneRepository } from 'src/domain/repositories/zone.repository';
import { TOKEN_SERVICE_TOKEN } from '../ports/token-service.interface';
import type { ITokenService } from '../ports/token-service.interface';
import { CreateZoneDto } from '../dtos/create-zone.dto';
import { Zone } from 'src/domain/entities/zone.entity';
import { Inject } from '@nestjs/common';

export class CreateZoneUseCase {
  constructor(
    @Inject(ZONE_REPOSITORY_TOKEN)
    private readonly zoneRepository: IZoneRepository,
    @Inject(TOKEN_SERVICE_TOKEN) private readonly tokenService: ITokenService,
  ) {}

  async execute(dto: CreateZoneDto): Promise<void> {
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
  }
}
