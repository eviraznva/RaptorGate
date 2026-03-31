import { JsonZonePairRepository } from '../infrastructure/persistence/repositories/json-zone-pair.repository.js';
import { JsonZoneRepository } from '../infrastructure/persistence/repositories/json-zone.repository.js';
import { ZONE_PAIR_REPOSITORY_TOKEN } from '../domain/repositories/zone-pair.repository.js';
import { GetAllZonesUseCase } from '../application/use-cases/get-all-zones.use-case.js';
import { TOKEN_SERVICE_TOKEN } from '../application/ports/token-service.interface.js';
import { CreateZoneUseCase } from '../application/use-cases/create-zone.use-case.js';
import { DeleteZoneUseCase } from '../application/use-cases/delete-zone.use-case.js';
import { ZONE_REPOSITORY_TOKEN } from '../domain/repositories/zone.repository.js';
import { EditZoneUseCase } from '../application/use-cases/edit-zone.use-case.js';
import { ZoneController } from '../presentation/controllers/zone.controller.js';
import { TokenService } from '../infrastructure/adapters/jwt-token.service.js';
import { FileStore } from '../infrastructure/persistence/json/file-store.js';
import { Mutex } from '../infrastructure/persistence/json/file-mutex.js';
import { JwtService } from '@nestjs/jwt';
import { Module } from '@nestjs/common';

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
