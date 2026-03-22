import { ZONE_PAIR_REPOSITORY_TOKEN } from 'src/domain/repositories/zone-pair.repository';
import type { IZonePairRepository } from 'src/domain/repositories/zone-pair.repository';
import { ZONE_REPOSITORY_TOKEN } from 'src/domain/repositories/zone.repository';
import type { IZoneRepository } from 'src/domain/repositories/zone.repository';
import { TOKEN_SERVICE_TOKEN } from '../ports/token-service.interface';
import type { ITokenService } from '../ports/token-service.interface';
import { CreateZonePairDto } from '../dtos/create-zone-pair.dto';
import { ZonePair } from 'src/domain/entities/zone-pair.entity';
import { Inject, Injectable } from '@nestjs/common';
import { AccessTokenIsInvalidException } from 'src/domain/exceptions/acces-token-is-invalid.exception';
import { EntityNotFoundException } from 'src/domain/exceptions/entity-not-found-exception';
import { EntityAlreadyExistsException } from 'src/domain/exceptions/entity-already-exists-exception';

@Injectable()
export class CreateZonePairUseCase {
  constructor(
    @Inject(ZONE_PAIR_REPOSITORY_TOKEN)
    private readonly zonePairRepository: IZonePairRepository,
    @Inject(TOKEN_SERVICE_TOKEN) private readonly tokenService: ITokenService,
    @Inject(ZONE_REPOSITORY_TOKEN)
    private readonly zoneRepository: IZoneRepository,
  ) {}

  async execute(dto: CreateZonePairDto): Promise<void> {
    const claims = this.tokenService.decodeAccessToken(dto.accessToken);
    const srcZoneExists = await this.zoneRepository.findById(dto.srcZoneId);
    const dstZoneExists = await this.zoneRepository.findById(dto.dstZoneId);
    const zonePair = await this.zonePairRepository.findByZoneIds(
      dto.srcZoneId,
      dto.dstZoneId,
    );

    if (!claims) throw new AccessTokenIsInvalidException();

    if (!srcZoneExists)
      throw new EntityNotFoundException('zone', dto.srcZoneId);

    if (!dstZoneExists)
      throw new EntityNotFoundException('zone', dto.dstZoneId);

    if (zonePair)
      throw new EntityAlreadyExistsException(
        'Zone pair',
        'source and destination zone ids',
        `${dto.srcZoneId} and ${dto.dstZoneId}`,
      );

    const newZonePair = ZonePair.create(
      crypto.randomUUID(),
      dto.srcZoneId,
      dto.dstZoneId,
      dto.defaultPolicy,
      new Date(),
      claims.sub,
    );

    await this.zonePairRepository.save(newZonePair);
  }
}
