import { Body, Controller, Inject, Post } from "@nestjs/common";
import { ApiTags } from "@nestjs/swagger";
import { CreateBlacklistEntryUseCase } from "src/application/use-cases/create-blacklist-entry.use-case";
import { ExtractToken } from "../decorators/auth/extract-token.decorator";
import { CreateDnsBlacklistEntryDto } from "../dtos/create-dns-blacklist-entry.dto";
import { CreateDnsBlacklistEntryResponseDto } from "../dtos/create-dns-blacklist-entry-response.dto";

@ApiTags("Dns Blaclist")
@Controller("dns-blacklist")
export class DnsBlacklistController {
  constructor(
    @Inject(CreateBlacklistEntryUseCase)
    private readonly createBlacklistEntryUseCase: CreateBlacklistEntryUseCase,
  ) {}

  @Post()
  async createDnsBlacklistEntry(
    @ExtractToken() accessToken: string,
    @Body() dto: CreateDnsBlacklistEntryDto,
  ): Promise<CreateDnsBlacklistEntryResponseDto> {
    const result = await this.createBlacklistEntryUseCase.execute({
      ...dto,
      accessToken,
    });

    const dnsBlacklistEntries = result.entry.map((entry) => {
      return {
        id: entry.getId(),
        domain: entry.getDomain(),
        reason: entry.getReason(),
        isActive: entry.getIsActive(),
        createdAt: entry.getCreatedAt().toISOString(),
        createdBy: entry.getCreatedBy(),
      };
    });

    return {
      entry: dnsBlacklistEntries,
    };
  }
}
