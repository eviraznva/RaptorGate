import { Inject, Injectable } from "@nestjs/common";
import {
  DNS_INSPECTION_REPOSITORY_TOKEN,
  type IDnsInspectionRepository,
} from "../../domain/repositories/dns-inspection.repository.js";
import { GetDnsInspectionConfigDto } from "../dtos/get-dns-inspection-config.dto.js";

@Injectable()
export class GetDnsInspectionConfigUseCase {
  constructor(
    @Inject(DNS_INSPECTION_REPOSITORY_TOKEN)
    private readonly repository: IDnsInspectionRepository,
  ) {}

  async execute(): Promise<GetDnsInspectionConfigDto> {
    const dnsInspection = await this.repository.get();
    return { dnsInspection };
  }
}
