import { JsonRuleRepository } from 'src/infrastructure/persistence/repositories/json-rule.repository';
import { GetAllRulesUseCase } from 'src/application/use-cases/get-all-rules.use-case';
import { TOKEN_SERVICE_TOKEN } from 'src/application/ports/token-service.interface';
import { CreateRuleUseCase } from 'src/application/use-cases/create-rule.use-case';
import { DeleteRuleUseCase } from 'src/application/use-cases/delete-rule.use-case';
import { RULES_REPOSITORY_TOKEN } from 'src/domain/repositories/rules-repository';
import { EditRuleUseCase } from 'src/application/use-cases/edit-rule.use-case';
import { RulesController } from 'src/presentation/controllers/rule.controller';
import { TokenService } from 'src/infrastructure/adapters/jwt-token.service';
import { FileStore } from 'src/infrastructure/persistence/json/file-store';
import { Mutex } from 'src/infrastructure/persistence/json/file-mutex';
import { JwtService } from '@nestjs/jwt';
import { Module } from '@nestjs/common';

@Module({
  imports: [],
  controllers: [RulesController],
  providers: [
    GetAllRulesUseCase,
    EditRuleUseCase,
    DeleteRuleUseCase,
    CreateRuleUseCase,
    FileStore,
    Mutex,
    {
      provide: TOKEN_SERVICE_TOKEN,
      useClass: TokenService,
    },
    {
      provide: RULES_REPOSITORY_TOKEN,
      useClass: JsonRuleRepository,
    },
    JwtService,
  ],
})
export class RulesModule {}
