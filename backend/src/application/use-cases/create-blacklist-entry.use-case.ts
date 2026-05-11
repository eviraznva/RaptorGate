import { Inject } from "@nestjs/common";
import { DnsBlacklistEntry } from "src/domain/entities/dns-blacklist-entry.entity";
import { AccessTokenIsInvalidException } from "src/domain/exceptions/acces-token-is-invalid.exception";
import {
  DNS_BLACLIST_REPOSITORY_TOKEN,
  type IDnsBlacklistRepository,
} from "src/domain/repositories/dns-blacklist.repository";
import { DomainName } from "src/domain/value-objects/domain-name.vo";
import { CreateBlacklistEntryDto } from "../dtos/create-blacklist-entry.dto";
import { CreateDnsBlacklistEntryResponseDto } from "../dtos/create-blacklist-entry-response.dto";
import {
  type ITokenService,
  TOKEN_SERVICE_TOKEN,
} from "../ports/token-service.interface";

export class CreateBlacklistEntryUseCase {
  constructor(
    @Inject(TOKEN_SERVICE_TOKEN) private readonly tokenService: ITokenService,
    @Inject(DNS_BLACLIST_REPOSITORY_TOKEN)
    private readonly dnsBlacklistRepository: IDnsBlacklistRepository,
  ) {}

  async execute(
    dto: CreateBlacklistEntryDto,
  ): Promise<CreateDnsBlacklistEntryResponseDto> {
    const claims = this.tokenService.decodeAccessToken(dto.accessToken);
    if (!claims) throw new AccessTokenIsInvalidException();

    const newDnsBlacklistEntries = dto.domain.map((domain) => {
      const dnsEntry = DnsBlacklistEntry.create(
        crypto.randomUUID(),
        DomainName.create(domain),
        dto.reason,
        dto.isActive,
        new Date(),
        claims.sub,
      );

      return dnsEntry;
    });

    await Promise.all(
      newDnsBlacklistEntries.map(
        async (entry) => await this.dnsBlacklistRepository.save(entry),
      ),
    );

    return { entry: newDnsBlacklistEntries };
  }
}
