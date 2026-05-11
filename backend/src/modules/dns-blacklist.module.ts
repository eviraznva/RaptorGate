import { Module } from "@nestjs/common";
import { JwtService } from "@nestjs/jwt";
import { TOKEN_SERVICE_TOKEN } from "src/application/ports/token-service.interface";
import { CreateBlacklistEntryUseCase } from "src/application/use-cases/create-blacklist-entry.use-case";
import { DNS_BLACLIST_REPOSITORY_TOKEN } from "src/domain/repositories/dns-blacklist.repository";
import { TokenService } from "src/infrastructure/adapters/jwt-token.service";
import { Mutex } from "src/infrastructure/persistence/json/file-mutex";
import { FileStore } from "src/infrastructure/persistence/json/file-store";
import { JsonDnsBlacklistRepository } from "src/infrastructure/persistence/repositories/json-dns-blacklist.repository";
import { DnsBlacklistController } from "src/presentation/controllers/dns-blacklist.controller";

@Module({
  imports: [],
  controllers: [DnsBlacklistController],
  providers: [
    CreateBlacklistEntryUseCase,
    FileStore,
    Mutex,
    {
      provide: DNS_BLACLIST_REPOSITORY_TOKEN,
      useClass: JsonDnsBlacklistRepository,
    },
    {
      provide: TOKEN_SERVICE_TOKEN,
      useClass: TokenService,
    },
    JwtService,
  ],
})
export class DnsBlacklistModule {}
