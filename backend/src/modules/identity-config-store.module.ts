import { Module } from '@nestjs/common';
import { IDENTITY_CONFIG_REPOSITORY_TOKEN } from '../domain/repositories/identity-config.repository.js';
import { Mutex } from '../infrastructure/persistence/json/file-mutex.js';
import { FileStore } from '../infrastructure/persistence/json/file-store.js';
import { JsonIdentityConfigRepository } from '../infrastructure/persistence/repositories/json-identity-config.repository.js';

@Module({
  providers: [
    FileStore,
    Mutex,
    JsonIdentityConfigRepository,
    {
      provide: IDENTITY_CONFIG_REPOSITORY_TOKEN,
      useExisting: JsonIdentityConfigRepository,
    },
  ],
  exports: [IDENTITY_CONFIG_REPOSITORY_TOKEN],
})
export class IdentityConfigStoreModule {}
