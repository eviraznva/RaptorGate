import { ZONE_PAIR_REPOSITORY_TOKEN } from 'src/domain/repositories/zone-pair.repository';
import type { IZonePairRepository } from 'src/domain/repositories/zone-pair.repository';
import { ZONE_REPOSITORY_TOKEN } from 'src/domain/repositories/zone.repository';
import type { IZoneRepository } from 'src/domain/repositories/zone.repository';
import { TOKEN_SERVICE_TOKEN } from '../ports/token-service.interface';
import type { ITokenService } from '../ports/token-service.interface';
import { CreateZonePairDto } from '../dtos/create-zone-pair.dto';
import { ZonePair } from 'src/domain/entities/zone-pair.entity';
import { Inject, Injectable } from '@nestjs/common';

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

    if (!claims) throw new Error('Invalid access token');

    if (!srcZoneExists)
      throw new Error(`Source zone with id ${dto.srcZoneId} not found`);

    if (!dstZoneExists)
      throw new Error(`Destination zone with id ${dto.dstZoneId} not found`);

    if (zonePair) throw new Error('Zone pair already exists');

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
