import { JsonZonePairRepository } from 'src/infrastructure/persistence/repositories/json-zone-pair.repository';
import { JsonZoneRepository } from 'src/infrastructure/persistence/repositories/json-zone.repository';
import { GetAllZonePairsUseCase } from 'src/application/use-cases/get-all-zone-pairs.use-case';
import { CreateZonePairUseCase } from 'src/application/use-cases/create-zone-pair.use-case';
import { DeleteZonePairUseCase } from 'src/application/use-cases/delete-zone-pair.use-case';
import { ZONE_PAIR_REPOSITORY_TOKEN } from 'src/domain/repositories/zone-pair.repository';
import { ZonePairsController } from 'src/presentation/controllers/zone-pairs.controller';
import { EditZonePairUseCase } from 'src/application/use-cases/edit-zone-pair.use-case';
import { TOKEN_SERVICE_TOKEN } from 'src/application/ports/token-service.interface';
import { ZONE_REPOSITORY_TOKEN } from 'src/domain/repositories/zone.repository';
import { TokenService } from 'src/infrastructure/adapters/jwt-token.service';
import { FileStore } from 'src/infrastructure/persistence/json/file-store';
import { Mutex } from 'src/infrastructure/persistence/json/file-mutex';
import { Module } from '@nestjs/common';
import { JwtService } from '@nestjs/jwt';

@Module({
  imports: [],
  controllers: [ZonePairsController],
  providers: [
    CreateZonePairUseCase,
    GetAllZonePairsUseCase,
    EditZonePairUseCase,
    DeleteZonePairUseCase,
    Mutex,
    FileStore,
    {
      provide: ZONE_PAIR_REPOSITORY_TOKEN,
      useClass: JsonZonePairRepository,
    },
    {
      provide: ZONE_REPOSITORY_TOKEN,
      useClass: JsonZoneRepository,
    },
    {
      provide: TOKEN_SERVICE_TOKEN,
      useClass: TokenService,
    },
    JwtService,
  ],
})
export class ZonePairsModule {}
