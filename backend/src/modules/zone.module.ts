import { JsonZonePairRepository } from 'src/infrastructure/persistence/repositories/json-zone-pair.repository';
import { JsonZoneRepository } from 'src/infrastructure/persistence/repositories/json-zone.repository';
import { ZONE_PAIR_REPOSITORY_TOKEN } from 'src/domain/repositories/zone-pair.repository';
import { GetAllZonesUseCase } from 'src/application/use-cases/get-all-zones.use-case';
import { TOKEN_SERVICE_TOKEN } from 'src/application/ports/token-service.interface';
import { CreateZoneUseCase } from 'src/application/use-cases/create-zone.use-case';
import { DeleteZoneUseCase } from 'src/application/use-cases/delete-zone.use-case';
import { ZONE_REPOSITORY_TOKEN } from 'src/domain/repositories/zone.repository';
import { EditZoneUseCase } from 'src/application/use-cases/edit-zone.use-case';
import { ZoneController } from 'src/presentation/controllers/zone.controller';
import { TokenService } from 'src/infrastructure/adapters/jwt-token.service';
import { FileStore } from 'src/infrastructure/persistence/json/file-store';
import { Mutex } from 'src/infrastructure/persistence/json/file-mutex';
import { Module } from '@nestjs/common';
import { JwtService } from '@nestjs/jwt';

@Module({
  imports: [],
  controllers: [ZoneController],
  providers: [
    CreateZoneUseCase,
    GetAllZonesUseCase,
    EditZoneUseCase,
    DeleteZoneUseCase,
    FileStore,
    Mutex,
    {
      provide: ZONE_REPOSITORY_TOKEN,
      useClass: JsonZoneRepository,
    },
    {
      provide: ZONE_PAIR_REPOSITORY_TOKEN,
      useClass: JsonZonePairRepository,
    },
    {
      provide: TOKEN_SERVICE_TOKEN,
      useClass: TokenService,
    },
    JwtService,
  ],
})
export class ZoneModule {}
