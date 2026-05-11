import { Inject, Injectable } from '@nestjs/common';
import { SecretNotFoundException } from '../../domain/exceptions/secret-not-found.exception.js';
import {
  type ISecretStoreRepository,
  SECRET_STORE_REPOSITORY_TOKEN,
} from '../../domain/repositories/secret-store.repository.js';
import { SecretRef } from '../../domain/value-objects/secret-ref.vo.js';
import type { SecretMetadataDto } from '../dtos/secret-metadata.dto.js';

export interface GetSecretMetadataCommand {
  scope: string;
  type: string;
  name: string;
}

@Injectable()
export class GetSecretMetadataUseCase {
  constructor(
    @Inject(SECRET_STORE_REPOSITORY_TOKEN)
    private readonly secretStoreRepository: ISecretStoreRepository,
  ) {}

  async execute(command: GetSecretMetadataCommand): Promise<SecretMetadataDto> {
    const ref = SecretRef.create(
      `secret://${command.scope}/${command.type}/${command.name}`,
    ).getValue();
    const record = await this.secretStoreRepository.findByRef(ref);
    if (!record) throw new SecretNotFoundException(ref);

    return {
      ref: record.getRef(),
      createdAt: record.getCreatedAt(),
      updatedAt: record.getUpdatedAt(),
      updatedBy: record.getUpdatedBy(),
    };
  }
}
