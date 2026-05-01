import { jest } from '@jest/globals';
import { IdentityConfiguration } from '../../domain/entities/identity-configuration.entity.js';
import type { IIdentityConfigRepository } from '../../domain/repositories/identity-config.repository.js';
import type { ITokenService } from '../ports/token-service.interface.js';
import { IdentityConfigMutationService } from '../services/identity-config-mutation.service.js';
import type { IdentitySecretReferenceValidatorService } from '../services/identity-secret-reference-validator.service.js';
import { CreateRadiusProfileUseCase } from './create-radius-profile.use-case.js';

describe('CreateRadiusProfileUseCase', () => {
  it('creates a radius profile, validates secret refs and saves identity config', async () => {
    const repository = {
      mutate: jest.fn(async (transform: (config: IdentityConfiguration) => IdentityConfiguration | Promise<IdentityConfiguration>) =>
        transform(IdentityConfiguration.empty()),
      ),
    } as unknown as jest.Mocked<IIdentityConfigRepository>;
    const validator = {
      validateActiveConfig: jest.fn(async () => undefined),
    } as unknown as jest.Mocked<IdentitySecretReferenceValidatorService>;
    const useCase = new CreateRadiusProfileUseCase(
      repository,
      new IdentityConfigMutationService(),
      validator,
      {
        decodeAccessToken: jest.fn(() => ({ sub: 'user-1', username: 'admin' })),
      } as unknown as ITokenService,
    );

    const result = await useCase.execute({
      accessToken: 'token',
      name: 'Corp Radius',
      description: null,
      isActive: true,
      host: '10.0.0.10',
      port: 1812,
      sharedSecretRef: 'secret://identity/radius/corp',
      timeoutMs: 3000,
      retries: 1,
      nasIp: null,
      nasIdentifier: null,
      calledStationId: null,
    });

    expect(result.getRadiusServerProfiles()).toHaveLength(1);
    expect(result.getRadiusServerProfiles()[0].getCreatedBy()).toBe('user-1');
    expect(validator.validateActiveConfig).toHaveBeenCalledWith(result);
    expect(repository.mutate).toHaveBeenCalled();
  });
});
