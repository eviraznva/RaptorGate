import { JsonZonePairRepository } from "../infrastructure/persistence/repositories/json-zone-pair.repository.js";
import { JsonZoneRepository } from "../infrastructure/persistence/repositories/json-zone.repository.js";
import { GetAllZonePairsUseCase } from "../application/use-cases/get-all-zone-pairs.use-case.js";
import { CreateZonePairUseCase } from "../application/use-cases/create-zone-pair.use-case.js";
import { DeleteZonePairUseCase } from "../application/use-cases/delete-zone-pair.use-case.js";
import { ZONE_PAIR_REPOSITORY_TOKEN } from "../domain/repositories/zone-pair.repository.js";
import { ZonePairsController } from "../presentation/controllers/zone-pairs.controller.js";
import { EditZonePairUseCase } from "../application/use-cases/edit-zone-pair.use-case.js";
import { TOKEN_SERVICE_TOKEN } from "../application/ports/token-service.interface.js";
import { ZONE_REPOSITORY_TOKEN } from "../domain/repositories/zone.repository.js";
import { TokenService } from "../infrastructure/adapters/jwt-token.service.js";
import { FileStore } from "../infrastructure/persistence/json/file-store.js";
import { Mutex } from "../infrastructure/persistence/json/file-mutex.js";
import { JwtService } from "@nestjs/jwt";
import { Module } from "@nestjs/common";

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
