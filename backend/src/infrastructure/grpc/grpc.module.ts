import { JsonConfigSnapshotRepository } from '../persistence/repositories/json-config-snapshot.repository';
import { CONFIG_SNAPSHOT_REPOSITORY_TOKEN } from '../../domain/repositories/config-snapshot.repository';
import { GetActiveConfigUseCase } from '../../application/use-cases/get-active-config.use-case';
import { RaptorGateController } from './raptorgate.controller';
import { CaCertStore } from '../stores/ca-cert.store';
import { FileStore } from '../persistence/json/file-store';
import { Mutex } from '../persistence/json/file-mutex';
import { Module } from '@nestjs/common';

@Module({
  imports: [],
  controllers: [RaptorGateController],
  providers: [
    GetActiveConfigUseCase,
    CaCertStore,
    FileStore,
    Mutex,
    {
      provide: CONFIG_SNAPSHOT_REPOSITORY_TOKEN,
      useClass: JsonConfigSnapshotRepository,
    },
  ],
  exports: [CaCertStore],
})
export class GrpcModule {}
