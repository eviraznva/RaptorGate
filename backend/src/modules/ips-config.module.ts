import { Module } from "@nestjs/common";
import { GetIpsConfigurationUseCase } from "src/application/use-cases/get-ips-configuration.use-case";
import { UpdateIpsConfigUseCase } from "src/application/use-cases/update-ips-config.use-case";
import { IPS_CONFIG_REPOSITORY_TOKEN } from "src/domain/repositories/ips-config.repository";
import { Mutex } from "src/infrastructure/persistence/json/file-mutex";
import { FileStore } from "src/infrastructure/persistence/json/file-store";
import { JsonIpsConfigRepository } from "src/infrastructure/persistence/repositories/json-ips-config.repository";
import { IpsConfigController } from "src/presentation/controllers/ips-config.controller";

@Module({
  imports: [],
  controllers: [IpsConfigController],
  providers: [
    GetIpsConfigurationUseCase,
    UpdateIpsConfigUseCase,
    FileStore,
    Mutex,
    {
      provide: IPS_CONFIG_REPOSITORY_TOKEN,
      useClass: JsonIpsConfigRepository,
    },
  ],
})
export class IpsConfigModule {}
