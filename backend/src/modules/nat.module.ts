import { JsonNatRuleRepository } from 'src/infrastructure/persistence/repositories/json-nat-rule.repository';
import { GetAllNatRulesUseCase } from 'src/application/use-cases/get-all-nat-rules.use-case';
import { CreateNatRuleUseCase } from 'src/application/use-cases/create-nat-rule.use-case';
import { NAT_RULES_REPOSITORY_TOKEN } from 'src/domain/repositories/nat-rules.repository';
import { DeleteNatRuleUseCase } from 'src/application/use-cases/delete-nat-rule.use-case';
import { EditNatRuleUseCase } from 'src/application/use-cases/edit-nat-rule.use-case';
import { NatRuleController } from 'src/presentation/controllers/nat-rule.controller';
import { TOKEN_SERVICE_TOKEN } from 'src/application/ports/token-service.interface';
import { TokenService } from 'src/infrastructure/adapters/jwt-token.service';
import { FileStore } from 'src/infrastructure/persistence/json/file-store';
import { Mutex } from 'src/infrastructure/persistence/json/file-mutex';
import { JwtService } from '@nestjs/jwt';
import { Module } from '@nestjs/common';

@Module({
  imports: [],
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
