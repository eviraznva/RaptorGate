import { Inject, Injectable } from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import {
  type ISecretStoreRepository,
  SECRET_STORE_REPOSITORY_TOKEN,
} from '../../domain/repositories/secret-store.repository.js';
import { SecretNotFoundException } from '../../domain/exceptions/secret-not-found.exception.js';
import { SecretRef } from '../../domain/value-objects/secret-ref.vo.js';
import { SecretValue } from '../../domain/value-objects/secret-value.vo.js';
import type { Env } from '../../shared/config/env.validation.js';
import {
  type ISecretCryptoService,
  SECRET_CRYPTO_SERVICE_TOKEN,
} from '../ports/secret-crypto.service.js';
import type { ISecretResolverService } from '../ports/secret-resolver.service.js';

@Injectable()
export class SecretResolverService implements ISecretResolverService {
  constructor(
    private readonly configService: ConfigService<Env, true>,
    @Inject(SECRET_STORE_REPOSITORY_TOKEN)
    private readonly secretStoreRepository: ISecretStoreRepository,
    @Inject(SECRET_CRYPTO_SERVICE_TOKEN)
    private readonly secretCryptoService: ISecretCryptoService,
  ) {}

  async resolve(ref: string): Promise<SecretValue> {
    const validatedRef = SecretRef.create(ref).getValue();

    if (validatedRef.startsWith('env:')) {
      return this.resolveEnvRef(validatedRef);
    }

    const record = await this.secretStoreRepository.findByRef(validatedRef);
    if (!record) throw new SecretNotFoundException(validatedRef);

    return this.secretCryptoService.decrypt({
      ciphertext: record.getCiphertext(),
      iv: record.getIv(),
      authTag: record.getAuthTag(),
    });
  }

  private resolveEnvRef(ref: string): SecretValue {
    const envName = ref.slice('env:'.length) as keyof Env;
    const value = this.configService.get(envName, { infer: true });

    if (typeof value !== 'string' || value.length === 0) {
      throw new SecretNotFoundException(ref);
    }

    return SecretValue.create(value);
  }
}
