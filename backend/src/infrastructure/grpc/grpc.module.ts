import { JsonConfigSnapshotRepository } from '../persistence/repositories/json-config-snapshot.repository';
import { CONFIG_SNAPSHOT_REPOSITORY_TOKEN } from 'src/domain/repositories/config-snapshot.repository';
import { GetActiveConfigUseCase } from 'src/application/use-cases/get-active-config.use-case';
import { RaptorGateController } from './raptorgate.controller';
import { Module } from '@nestjs/common';
import { Mutex } from '../persistence/json/file-mutex';
import { FileStore } from '../persistence/json/file-store';

@Module({
  imports: [],
  controllers: [RaptorGateController],
  providers: [
    GetActiveConfigUseCase,
    Mutex,
    FileStore,
    {
      provide: CONFIG_SNAPSHOT_REPOSITORY_TOKEN,
      useClass: JsonConfigSnapshotRepository,
    },
  ],
})
export class GrpcModule {}
