import { Inject, Injectable } from '@nestjs/common';
import { SecretRecord } from '../../domain/entities/secret-record.entity.js';
import { AccessTokenIsInvalidException } from '../../domain/exceptions/acces-token-is-invalid.exception.js';
import {
  type ISecretStoreRepository,
  SECRET_STORE_REPOSITORY_TOKEN,
} from '../../domain/repositories/secret-store.repository.js';
import { SecretRef } from '../../domain/value-objects/secret-ref.vo.js';
import { SecretValue } from '../../domain/value-objects/secret-value.vo.js';
import type { SecretMetadataDto } from '../dtos/secret-metadata.dto.js';
import {
  type ISecretCryptoService,
  SECRET_CRYPTO_SERVICE_TOKEN,
} from '../ports/secret-crypto.service.js';
import {
  type ITokenService,
  TOKEN_SERVICE_TOKEN,
} from '../ports/token-service.interface.js';

export interface UpsertSecretCommand {
  scope: string;
  type: string;
  name: string;
  value: string;
  accessToken: string;
}

@Injectable()
export class UpsertSecretUseCase {
  constructor(
    @Inject(SECRET_STORE_REPOSITORY_TOKEN)
    private readonly secretStoreRepository: ISecretStoreRepository,
    @Inject(SECRET_CRYPTO_SERVICE_TOKEN)
    private readonly secretCryptoService: ISecretCryptoService,
    @Inject(TOKEN_SERVICE_TOKEN)
    private readonly tokenService: ITokenService,
  ) {}

  async execute(command: UpsertSecretCommand): Promise<SecretMetadataDto> {
    const claims = this.tokenService.decodeAccessToken(command.accessToken);
    if (!claims) throw new AccessTokenIsInvalidException();

    const ref = this.buildRef(command);
    const existing = await this.secretStoreRepository.findByRef(ref);
    const encrypted = this.secretCryptoService.encrypt(
      SecretValue.create(command.value),
    );
    const now = new Date();
    const record = SecretRecord.create(
      ref,
      encrypted.ciphertext,
      encrypted.iv,
      encrypted.authTag,
      existing?.getCreatedAt() ?? now,
      now,
      claims.sub,
    );

    await this.secretStoreRepository.save(record);

    return this.toMetadata(record);
  }

  private buildRef(command: UpsertSecretCommand): string {
    return SecretRef.create(
      `secret://${command.scope}/${command.type}/${command.name}`,
    ).getValue();
  }

  private toMetadata(record: SecretRecord): SecretMetadataDto {
    return {
      ref: record.getRef(),
      createdAt: record.getCreatedAt(),
      updatedAt: record.getUpdatedAt(),
      updatedBy: record.getUpdatedBy(),
    };
  }
}
