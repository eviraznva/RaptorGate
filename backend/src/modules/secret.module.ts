import { Module } from '@nestjs/common';
import { JwtService } from '@nestjs/jwt';
import { TOKEN_SERVICE_TOKEN } from '../application/ports/token-service.interface.js';
import { SECRET_CRYPTO_SERVICE_TOKEN } from '../application/ports/secret-crypto.service.js';
import { SECRET_RESOLVER_SERVICE_TOKEN } from '../application/ports/secret-resolver.service.js';
import { SecretResolverService } from '../application/services/secret-resolver.service.js';
import { GetSecretMetadataUseCase } from '../application/use-cases/get-secret-metadata.use-case.js';
import { UpsertSecretUseCase } from '../application/use-cases/upsert-secret.use-case.js';
import { SECRET_STORE_REPOSITORY_TOKEN } from '../domain/repositories/secret-store.repository.js';
import { TokenService } from '../infrastructure/adapters/jwt-token.service.js';
import { Mutex } from '../infrastructure/persistence/json/file-mutex.js';
import { FileStore } from '../infrastructure/persistence/json/file-store.js';
import { JsonSecretStoreRepository } from '../infrastructure/persistence/repositories/json-secret-store.repository.js';
import { AesGcmSecretCryptoService } from '../infrastructure/secrets/aes-gcm-secret-crypto.service.js';
import { SecretController } from '../presentation/controllers/secret.controller.js';

@Module({
  controllers: [SecretController],
  providers: [
    GetSecretMetadataUseCase,
    UpsertSecretUseCase,
    SecretResolverService,
    JsonSecretStoreRepository,
    AesGcmSecretCryptoService,
    FileStore,
    Mutex,
    JwtService,
    {
      provide: TOKEN_SERVICE_TOKEN,
      useClass: TokenService,
    },
    {
      provide: SECRET_STORE_REPOSITORY_TOKEN,
      useExisting: JsonSecretStoreRepository,
    },
    {
      provide: SECRET_CRYPTO_SERVICE_TOKEN,
      useExisting: AesGcmSecretCryptoService,
    },
    {
      provide: SECRET_RESOLVER_SERVICE_TOKEN,
      useExisting: SecretResolverService,
    },
  ],
  exports: [
    SECRET_STORE_REPOSITORY_TOKEN,
    SECRET_CRYPTO_SERVICE_TOKEN,
    SECRET_RESOLVER_SERVICE_TOKEN,
    SecretResolverService,
  ],
})
export class SecretModule {}
