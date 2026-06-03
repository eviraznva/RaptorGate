import { randomUUID } from "node:crypto";
import {
  BadRequestException,
  Inject,
  Injectable,
  Logger,
} from "@nestjs/common";
import { ZoneInterface } from "../../domain/entities/zone-interface.entity.js";
import { AccessTokenIsInvalidException } from "../../domain/exceptions/acces-token-is-invalid.exception.js";
import { EntityNotFoundException } from "../../domain/exceptions/entity-not-found-exception.js";
import {
  type IZoneRepository,
  ZONE_REPOSITORY_TOKEN,
} from "../../domain/repositories/zone.repository.js";
import {
  type IZoneInterfaceRepository,
  ZONE_INTERFACE_REPOSITORY_TOKEN,
} from "../../domain/repositories/zone-interface.repository.js";
import type { CreateZoneInterfaceDto } from "../dtos/create-zone-interface.dto.js";
import type { CreateZoneInterfaceResponseDto } from "../dtos/create-zone-interface-response.dto.js";
import type { ITokenService } from "../ports/token-service.interface.js";
import { TOKEN_SERVICE_TOKEN } from "../ports/token-service.interface.js";
import { normalizeZoneInterfaceAddressesForConfig } from "../services/zone-interface-config-normalizer.js";

@Injectable()
export class CreateZoneInterfaceUseCase {
  private readonly logger = new Logger(CreateZoneInterfaceUseCase.name);

  constructor(
    @Inject(ZONE_INTERFACE_REPOSITORY_TOKEN)
    private readonly zoneInterfaceRepository: IZoneInterfaceRepository,
    @Inject(ZONE_REPOSITORY_TOKEN)
    private readonly zoneRepository: IZoneRepository,
    @Inject(TOKEN_SERVICE_TOKEN) private readonly tokenService: ITokenService,
  ) {}

  async execute(
    dto: CreateZoneInterfaceDto,
  ): Promise<CreateZoneInterfaceResponseDto> {
    const claims = this.tokenService.decodeAccessToken(dto.accessToken);
    if (!claims) throw new AccessTokenIsInvalidException();

    const parent = await this.zoneInterfaceRepository.findById(
      dto.parentInterfaceId,
    );
    if (!parent) {
      throw new EntityNotFoundException(
        "parent zone interface",
        dto.parentInterfaceId,
      );
    }
    if (parent.getVlanId() !== null) {
      throw new BadRequestException(
        "Cannot create VLAN on a VLAN subinterface — parent must be a physical interface",
      );
    }

    const zone = await this.zoneRepository.findById(dto.zoneId);
    if (!zone) {
      throw new EntityNotFoundException("zone", dto.zoneId);
    }

    const existingVlans = await this.zoneInterfaceRepository.findAll();
    const duplicateVlan = existingVlans.find(
      (zi) =>
        zi.getParentInterfaceId() === dto.parentInterfaceId &&
        zi.getVlanId() === dto.vlanId,
    );
    if (duplicateVlan) {
      throw new BadRequestException(
        `VLAN ${dto.vlanId} already exists on parent interface ${parent.getInterfaceName()}`,
      );
    }

    const addresses = this.buildAddresses(
      dto.ipv4Address,
      dto.ipv4Mask,
      dto.ipv6Address,
      dto.ipv6Mask,
    );

    const displayName = `${parent.getInterfaceName()}.${dto.vlanId}`;

    const zoneInterface = ZoneInterface.create(
      randomUUID(),
      dto.zoneId,
      displayName,
      dto.vlanId,
      dto.isActive !== false ? "active" : "inactive",
      normalizeZoneInterfaceAddressesForConfig(dto.vlanId, addresses),
      new Date(),
      dto.sniffed ?? false,
      dto.parentInterfaceId,
    );

    await this.zoneInterfaceRepository.save(zoneInterface);

    this.logger.log({
      event: "zone_interface.create.succeeded",
      message: "VLAN subinterface created",
      actorId: claims.sub,
      zoneInterfaceId: zoneInterface.getId(),
      parentInterfaceId: dto.parentInterfaceId,
      vlanId: dto.vlanId,
    });

    return { zoneInterface };
  }

  private buildAddresses(
    ipv4Address: string | null | undefined,
    ipv4Mask: number | null | undefined,
    ipv6Address: string | null | undefined,
    ipv6Mask: number | null | undefined,
  ): string[] {
    const addresses: string[] = [];

    if (ipv4Address && ipv4Mask != null) {
      addresses.push(`${ipv4Address}/${ipv4Mask}`);
    }
    if (ipv6Address && ipv6Mask != null) {
      addresses.push(`${ipv6Address}/${ipv6Mask}`);
    }

    return addresses;
  }
}
