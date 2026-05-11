import { Module } from "@nestjs/common";
import { JwtService } from "@nestjs/jwt";
import { TOKEN_SERVICE_TOKEN } from "../application/ports/token-service.interface.js";
import { CreateNatRuleUseCase } from "../application/use-cases/create-nat-rule.use-case.js";
import { DeleteNatRuleUseCase } from "../application/use-cases/delete-nat-rule.use-case.js";
import { EditNatRuleUseCase } from "../application/use-cases/edit-nat-rule.use-case.js";
import { GetAllNatRulesUseCase } from "../application/use-cases/get-all-nat-rules.use-case.js";
import { NAT_RULES_REPOSITORY_TOKEN } from "../domain/repositories/nat-rules.repository.js";
import { TokenService } from "../infrastructure/adapters/jwt-token.service.js";
import { Mutex } from "../infrastructure/persistence/json/file-mutex.js";
import { FileStore } from "../infrastructure/persistence/json/file-store.js";
import { JsonNatRuleRepository } from "../infrastructure/persistence/repositories/json-nat-rule.repository.js";
import { NatRuleController } from "../presentation/controllers/nat-rule.controller.js";

@Module({
  controllers: [NatRuleController],
  providers: [
    CreateNatRuleUseCase,
    GetAllNatRulesUseCase,
    EditNatRuleUseCase,
    DeleteNatRuleUseCase,
    Mutex,
    FileStore,
    {
      provide: NAT_RULES_REPOSITORY_TOKEN,
      useClass: JsonNatRuleRepository,
    },
    {
      provide: TOKEN_SERVICE_TOKEN,
      useClass: TokenService,
    },
    JwtService,
  ],
})
export class NatModule {}
