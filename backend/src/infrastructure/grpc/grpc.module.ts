import { Module } from '@nestjs/common';
import { GetActiveConfigUseCase } from '../../application/use-cases/get-active-config.use-case.js';
import { CONFIG_SNAPSHOT_REPOSITORY_TOKEN } from '../../domain/repositories/config-snapshot.repository.js';
import { Mutex } from '../persistence/json/file-mutex.js';
import { FileStore } from '../persistence/json/file-store.js';
import { JsonConfigSnapshotRepository } from '../persistence/repositories/json-config-snapshot.repository.js';
import { RaptorGateController } from './raptorgate.controller.js';

@Module({
  imports: [],
  controllers: [RaptorGateController],
  providers: [
    GetActiveConfigUseCase,
    FileStore,
    Mutex,
    {
      provide: CONFIG_SNAPSHOT_REPOSITORY_TOKEN,
      useClass: JsonConfigSnapshotRepository,
    },
  ],
})
export class GrpcModule {}
