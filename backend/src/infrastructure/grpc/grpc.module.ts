import { CONFIG_SNAPSHOT_REPOSITORY_TOKEN } from 'src/domain/repositories/config-snapshot.repository';
import { DrizzleConfigSnapshotRepository } from '../persistence/repositories/drizzle-config-snapshot.repository';
import { GetActiveConfigUseCase } from 'src/application/use-cases/get-active-config.use-case';
import { RaptorGateController } from './raptorgate.controller';
import { CaCertStore } from '../stores/ca-cert.store';
import { Module } from '@nestjs/common';

@Module({
  imports: [],
  controllers: [RaptorGateController],
  providers: [
    GetActiveConfigUseCase,
    CaCertStore,
    {
      provide: CONFIG_SNAPSHOT_REPOSITORY_TOKEN,
      useClass: DrizzleConfigSnapshotRepository,
    },
  ],
  exports: [CaCertStore],
})
export class GrpcModule {}
