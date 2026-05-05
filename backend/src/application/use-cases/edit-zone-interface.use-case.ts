import {
  BadRequestException,
  Inject,
  Injectable,
  Logger,
} from "@nestjs/common";
import { ZoneInterface } from "../../domain/entities/zone-interface.entity.js";
import { AccessTokenIsInvalidException } from "../../domain/exceptions/acces-token-is-invalid.exception.js";
import { AtLeastOneFieldRequiredException } from "../../domain/exceptions/at-least-one-field-required.exception.js";
import { EntityNotFoundException } from "../../domain/exceptions/entity-not-found-exception.js";
import {
  type IZoneRepository,
  ZONE_REPOSITORY_TOKEN,
} from "../../domain/repositories/zone.repository.js";
import {
  type IZoneInterfaceRepository,
  ZONE_INTERFACE_REPOSITORY_TOKEN,
} from "../../domain/repositories/zone-interface.repository.js";
import type { EditZoneInterfaceDto } from "../dtos/edit-zone-interface.dto.js";
import type { EditZoneInterfaceResponseDto } from "../dtos/edit-zone-interface-response.dto.js";
import {
  FIREWALL_ZONE_QUERY_SERVICE_TOKEN,
  type IFirewallZoneQueryService,
} from "../ports/firewall-zone-query-service.interface.js";
import type { ITokenService } from "../ports/token-service.interface.js";
import { TOKEN_SERVICE_TOKEN } from "../ports/token-service.interface.js";

const NO_ZONE_ID = "00000000-0000-0000-0000-000000000000";

@Injectable()
export class EditZoneInterfaceUseCase {
  private readonly logger = new Logger(EditZoneInterfaceUseCase.name);

  constructor(
    @Inject(FIREWALL_ZONE_QUERY_SERVICE_TOKEN)
    private readonly firewallZoneQueryService: IFirewallZoneQueryService,
    @Inject(ZONE_INTERFACE_REPOSITORY_TOKEN)
    private readonly zoneInterfaceRepository: IZoneInterfaceRepository,
    @Inject(ZONE_REPOSITORY_TOKEN)
    private readonly zoneRepository: IZoneRepository,
    @Inject(TOKEN_SERVICE_TOKEN) private readonly tokenService: ITokenService,
  ) {}

  async execute(
    dto: EditZoneInterfaceDto,
  ): Promise<EditZoneInterfaceResponseDto> {
    const changedFields = Object.entries(dto)
      .filter(
        ([key, value]) =>
          key !== "id" && key !== "accessToken" && value !== undefined,
      )
      .map(([key]) => key);

    if (!changedFields.length) throw new AtLeastOneFieldRequiredException();

    const claims = this.tokenService.decodeAccessToken(dto.accessToken);
    if (!claims) throw new AccessTokenIsInvalidException();

    if (dto.zoneId && dto.zoneId !== NO_ZONE_ID) {
      const zone = await this.zoneRepository.findById(dto.zoneId);
      if (!zone) throw new EntityNotFoundException("zone", dto.zoneId);
    }

    const zoneInterfaces = await this.getZoneInterfaces(dto.id);
    const savedZoneInterface = zoneInterfaces.find(
      (zoneInterface) => zoneInterface.getId() === dto.id,
    );

    if (!savedZoneInterface) {
      throw new EntityNotFoundException("zone interface", dto.id);
    }

    const addresses = this.buildAddresses(
      dto,
      savedZoneInterface.getAddresses(),
    );
    // const firewallAddress = this.getFirewallAddress(dto, addresses);

    // if (this.shouldUpdateFirewallProperties(dto)) {
    //   await this.firewallZoneQueryService.updateZoneInterfaceProperties({
    //     id: dto.id,
    //     interfaceName: savedZoneInterface.getInterfaceName(),
    //     vlanId: dto.vlanId === null ? undefined : dto.vlanId,
    //     address: firewallAddress,
    //   });
    // }

    // if (dto.isActive !== undefined) {
    //   await this.firewallZoneQueryService.setInterfaceState(
    //     dto.id,
    //     dto.isActive,
    //   );
    // }

    const zoneInterface = ZoneInterface.create(
      savedZoneInterface.getId(),
      dto.zoneId ?? savedZoneInterface.getZoneId(),
      savedZoneInterface.getInterfaceName(),
      dto.vlanId !== undefined
        ? dto.vlanId
        : savedZoneInterface.getVlanId(),
      dto.isActive === undefined
        ? savedZoneInterface.getStatus()
        : dto.isActive
          ? "active"
          : "inactive",
      addresses,
      savedZoneInterface.getCreatedAt(),
    );

    await this.zoneInterfaceRepository.save(zoneInterface);

    this.logger.log({
      event: "zone_interface.update.succeeded",
      message: "zone interface updated",
      actorId: claims.sub,
      zoneInterfaceId: zoneInterface.getId(),
      changedFields,
    });

    return { zoneInterface };
  }

  private async getZoneInterfaces(id: string): Promise<ZoneInterface[]> {
    const savedZoneInterfaces = await this.zoneInterfaceRepository.findAll();
    if (savedZoneInterfaces.length) return savedZoneInterfaces;

    const liveZoneInterfaces =
      await this.firewallZoneQueryService.getLiveZoneInterfaces();

    if (
      !liveZoneInterfaces.some((zoneInterface) => zoneInterface.getId() === id)
    ) {
      throw new EntityNotFoundException("zone interface", id);
    }

    await this.zoneInterfaceRepository.overwriteAll(liveZoneInterfaces);

    return liveZoneInterfaces;
  }

  private shouldUpdateProperties(dto: EditZoneInterfaceDto): boolean {
    return (
      dto.vlanId !== undefined ||
      dto.ipv4Address !== undefined ||
      dto.ipv4Mask !== undefined ||
      dto.ipv6Address !== undefined ||
      dto.ipv6Mask !== undefined
    );
  }

  private shouldUpdateFirewallProperties(dto: EditZoneInterfaceDto): boolean {
    return (
      (dto.vlanId !== undefined && dto.vlanId !== null) ||
      dto.ipv4Address !== undefined ||
      dto.ipv4Mask !== undefined ||
      dto.ipv6Address !== undefined ||
      dto.ipv6Mask !== undefined
    );
  }

  private buildAddresses(
    dto: EditZoneInterfaceDto,
    currentAddresses: string[],
  ): string[] {
    const currentIpv4 = currentAddresses.find((address) =>
      address.includes("."),
    );
    const currentIpv6 = currentAddresses.find((address) =>
      address.includes(":"),
    );

    const nextIpv4 = this.buildAddress(
      dto.ipv4Address,
      dto.ipv4Mask,
      currentIpv4,
      "IPv4",
    );
    const nextIpv6 = this.buildAddress(
      dto.ipv6Address,
      dto.ipv6Mask,
      currentIpv6,
      "IPv6",
    );

    return [nextIpv4, nextIpv6].filter((address): address is string =>
      Boolean(address),
    );
  }

  private buildAddress(
    address: string | null | undefined,
    mask: number | null | undefined,
    currentAddress: string | undefined,
    label: string,
  ): string | undefined {
    if (address === undefined && mask === undefined) return currentAddress;
    if (address === null || mask === null) return undefined;

    if (address === undefined || mask === undefined) {
      throw new BadRequestException(
        `${label} address and mask must be provided together`,
      );
    }

    return `${address}/${mask}`;
  }

  private getFirewallAddress(
    dto: EditZoneInterfaceDto,
    addresses: string[],
  ): string | undefined {
    if (!this.shouldUpdateProperties(dto)) return undefined;

    return (
      addresses.find((address) => address.includes(".")) ??
      addresses.find((address) => address.includes(":"))
    );
  }
}
