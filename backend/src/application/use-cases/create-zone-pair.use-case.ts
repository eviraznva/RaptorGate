import { Inject, Injectable, Logger } from "@nestjs/common";
import { ZonePair } from "../../domain/entities/zone-pair.entity.js";
import { AccessTokenIsInvalidException } from "../../domain/exceptions/acces-token-is-invalid.exception.js";
import { EntityAlreadyExistsException } from "../../domain/exceptions/entity-already-exists-exception.js";
import { EntityNotFoundException } from "../../domain/exceptions/entity-not-found-exception.js";
import type { IZoneRepository } from "../../domain/repositories/zone.repository.js";
import { ZONE_REPOSITORY_TOKEN } from "../../domain/repositories/zone.repository.js";
import type { IZonePairRepository } from "../../domain/repositories/zone-pair.repository.js";
import { ZONE_PAIR_REPOSITORY_TOKEN } from "../../domain/repositories/zone-pair.repository.js";
import type { CreateZonePairDto } from "../dtos/create-zone-pair.dto.js";
import type { CreateZonePairResponseDto } from "../dtos/create-zone-pair-response.dto.js";
import type { ITokenService } from "../ports/token-service.interface.js";
import { TOKEN_SERVICE_TOKEN } from "../ports/token-service.interface.js";

@Injectable()
export class CreateZonePairUseCase {
  private readonly logger = new Logger(CreateZonePairUseCase.name);

  constructor(
    @Inject(ZONE_PAIR_REPOSITORY_TOKEN)
    private readonly zonePairRepository: IZonePairRepository,
    @Inject(TOKEN_SERVICE_TOKEN) private readonly tokenService: ITokenService,
    @Inject(ZONE_REPOSITORY_TOKEN)
    private readonly zoneRepository: IZoneRepository,
  ) {}

  async execute(dto: CreateZonePairDto): Promise<CreateZonePairResponseDto> {
    const claims = this.tokenService.decodeAccessToken(dto.accessToken);
    const srcZoneExists = await this.zoneRepository.findById(dto.srcZoneId);
    const dstZoneExists = await this.zoneRepository.findById(dto.dstZoneId);
    const zonePair = await this.zonePairRepository.findByZoneIds(
      dto.srcZoneId,
      dto.dstZoneId,
    );

    if (!claims) throw new AccessTokenIsInvalidException();

    if (!srcZoneExists)
      throw new EntityNotFoundException("zone", dto.srcZoneId);

    if (!dstZoneExists)
      throw new EntityNotFoundException("zone", dto.dstZoneId);

    if (zonePair)
      throw new EntityAlreadyExistsException(
        "Zone pair",
        "source and destination zone ids",
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

    this.logger.log({
      event: "zone_pair.create.succeeded",
      message: "zone pair created",
      actorId: claims.sub,
      zonePairId: newZonePair.getId(),
      srcZoneId: newZonePair.getSrcZoneId(),
      dstZoneId: newZonePair.getDstZoneId(),
      defaultPolicy: newZonePair.getDefaultPolicy(),
    });

    return { zonePair: newZonePair };
  }
}
