import {
  BadRequestException,
  Inject,
  Injectable,
  Logger,
} from "@nestjs/common";
import { AccessTokenIsInvalidException } from "../../domain/exceptions/acces-token-is-invalid.exception.js";
import { EntityNotFoundException } from "../../domain/exceptions/entity-not-found-exception.js";
import {
  type IZoneInterfaceRepository,
  ZONE_INTERFACE_REPOSITORY_TOKEN,
} from "../../domain/repositories/zone-interface.repository.js";
import type { ITokenService } from "../ports/token-service.interface.js";
import { TOKEN_SERVICE_TOKEN } from "../ports/token-service.interface.js";

@Injectable()
export class DeleteZoneInterfaceUseCase {
  private readonly logger = new Logger(DeleteZoneInterfaceUseCase.name);

  constructor(
    @Inject(ZONE_INTERFACE_REPOSITORY_TOKEN)
    private readonly zoneInterfaceRepository: IZoneInterfaceRepository,
    @Inject(TOKEN_SERVICE_TOKEN)
    private readonly tokenService: ITokenService,
  ) {}

  async execute(id: string, accessToken: string): Promise<void> {
    const claims = this.tokenService.decodeAccessToken(accessToken);
    if (!claims) throw new AccessTokenIsInvalidException();

    const zoneInterface = await this.zoneInterfaceRepository.findById(id);
    if (!zoneInterface) {
      throw new EntityNotFoundException("zone interface", id);
    }

    if (zoneInterface.getVlanId() === null) {
      throw new BadRequestException("Cannot delete physical interface");
    }

    await this.zoneInterfaceRepository.delete(id);

    this.logger.log({
      event: "zone_interface.delete.succeeded",
      message: "VLAN subinterface deleted",
      actorId: claims.sub,
      zoneInterfaceId: zoneInterface.getId(),
      vlanId: zoneInterface.getVlanId(),
      interfaceName: zoneInterface.getInterfaceName(),
    });
  }
}
