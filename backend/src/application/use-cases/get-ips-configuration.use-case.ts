import { Inject, Injectable, Logger } from "@nestjs/common";
import { EntityNotFoundException } from "src/domain/exceptions/entity-not-found-exception";
import {
  type IIpsConfigRepository,
  IPS_CONFIG_REPOSITORY_TOKEN,
} from "src/domain/repositories/ips-config.repository";
import { GetIpsConfigDto } from "../dtos/get-ips-config.dto";

@Injectable()
export class GetIpsConfigurationUseCase {
  private readonly logger = new Logger(GetIpsConfigurationUseCase.name);
  constructor(
    @Inject(IPS_CONFIG_REPOSITORY_TOKEN)
    private readonly ipsConfigRepository: IIpsConfigRepository,
  ) {}

  async execute(): Promise<GetIpsConfigDto> {
    const ipsConfig = await this.ipsConfigRepository.get();
    if (!ipsConfig) throw new EntityNotFoundException("ips config", "current");

    return { ipsConfig };
  }
}
