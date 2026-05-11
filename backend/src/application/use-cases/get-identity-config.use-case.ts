import { Inject, Injectable } from '@nestjs/common';
import type { IdentityConfiguration } from '../../domain/entities/identity-configuration.entity.js';
import {
  IDENTITY_CONFIG_REPOSITORY_TOKEN,
  type IIdentityConfigRepository,
} from '../../domain/repositories/identity-config.repository.js';

@Injectable()
export class GetIdentityConfigUseCase {
  constructor(
    @Inject(IDENTITY_CONFIG_REPOSITORY_TOKEN)
    private readonly identityConfigRepository: IIdentityConfigRepository,
  ) {}

  async execute(): Promise<IdentityConfiguration> {
    return this.identityConfigRepository.find();
  }
}
