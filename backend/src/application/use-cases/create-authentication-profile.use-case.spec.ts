import { jest } from '@jest/globals';
import { IdentityConfiguration } from '../../domain/entities/identity-configuration.entity.js';
import { IdentitySettings } from '../../domain/entities/identity-settings.entity.js';
import { RadiusServerProfile } from '../../domain/entities/radius-server-profile.entity.js';
import { IdentityProfileNotFoundException } from '../../domain/exceptions/identity-profile-not-found.exception.js';
import type { IIdentityConfigRepository } from '../../domain/repositories/identity-config.repository.js';
import type { ITokenService } from '../ports/token-service.interface.js';
import { IdentityConfigMutationService } from '../services/identity-config-mutation.service.js';
import type { IdentitySecretReferenceValidatorService } from '../services/identity-secret-reference-validator.service.js';
import { CreateAuthenticationProfileUseCase } from './create-authentication-profile.use-case.js';

describe('CreateAuthenticationProfileUseCase', () => {
  it('throws not found when the radius profile reference is missing', async () => {
    const now = new Date('2026-05-01T10:00:00.000Z');
    const radius = RadiusServerProfile.create(
      'radius-1',
      'Radius',
      null,
      true,
      '127.0.0.1',
      1812,
      'secret://identity/radius/default',
      3000,
      1,
      null,
      null,
      null,
      now,
      now,
      'creator',
    );
    const repository = {
      mutate: jest.fn(async (transform: (config: IdentityConfiguration) => IdentityConfiguration | Promise<IdentityConfiguration>) =>
        transform(
          IdentityConfiguration.create(
            [radius],
            [],
            [],
            IdentitySettings.create(null, null, null, null),
          ),
        ),
      ),
    } as unknown as jest.Mocked<IIdentityConfigRepository>;
    const validator = {
      validateActiveConfig: jest.fn(async () => undefined),
    } as unknown as jest.Mocked<IdentitySecretReferenceValidatorService>;
    const useCase = new CreateAuthenticationProfileUseCase(
      repository,
      new IdentityConfigMutationService(),
      validator,
      {
        decodeAccessToken: jest.fn(() => ({ sub: 'user-1', username: 'admin' })),
      } as unknown as ITokenService,
    );

    await expect(
      useCase.execute({
        accessToken: 'token',
        name: 'Portal auth',
        description: null,
        isActive: true,
        provider: 'radius',
        radiusProfileId: 'missing-radius',
        ldapProfileId: null,
        groupSource: 'radius_vsa',
        sessionTtlSeconds: 1800,
      }),
    ).rejects.toThrow(IdentityProfileNotFoundException);
  });
});
