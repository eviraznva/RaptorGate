import { Module } from '@nestjs/common';
import { GetDnsInspectionConfigUseCase } from '../application/use-cases/get-dns-inspection-config.use-case.js';
import { UpdateDnsInspectionConfigUseCase } from '../application/use-cases/update-dns-inspection-config.use-case.js';
import { DNS_INSPECTION_REPOSITORY_TOKEN } from '../domain/repositories/dns-inspection.repository.js';
import { Mutex } from '../infrastructure/persistence/json/file-mutex.js';
import { FileStore } from '../infrastructure/persistence/json/file-store.js';
import { JsonDnsInspectionRepository } from '../infrastructure/persistence/repositories/json-dns-inspection.repository.js';
import { DnsInspectionController } from '../presentation/controllers/dns-inspection.controller.js';

@Module({
  controllers: [DnsInspectionController],
  providers: [
    GetDnsInspectionConfigUseCase,
    UpdateDnsInspectionConfigUseCase,
    FileStore,
    Mutex,
    {
      provide: DNS_INSPECTION_REPOSITORY_TOKEN,
      useClass: JsonDnsInspectionRepository,
    },
  ],
})
export class DnsInspectionModule {}
