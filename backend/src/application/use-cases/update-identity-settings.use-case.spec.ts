import { jest } from '@jest/globals';
import { IdentityAuthenticationProfile } from '../../domain/entities/identity-authentication-profile.entity.js';
import { IdentityConfiguration } from '../../domain/entities/identity-configuration.entity.js';
import { IdentitySettings } from '../../domain/entities/identity-settings.entity.js';
import { RadiusServerProfile } from '../../domain/entities/radius-server-profile.entity.js';
import { IdentityProfileNotFoundException } from '../../domain/exceptions/identity-profile-not-found.exception.js';
import type { IIdentityConfigRepository } from '../../domain/repositories/identity-config.repository.js';
import type { ITokenService } from '../ports/token-service.interface.js';
import { IdentityConfigMutationService } from '../services/identity-config-mutation.service.js';
import type { IdentitySecretReferenceValidatorService } from '../services/identity-secret-reference-validator.service.js';
import { UpdateIdentitySettingsUseCase } from './update-identity-settings.use-case.js';

describe('UpdateIdentitySettingsUseCase', () => {
  it('updates portal and admin authentication profile references', async () => {
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
    const auth = IdentityAuthenticationProfile.create(
      'auth-1',
      'Auth',
      null,
      true,
      'radius',
      'radius-1',
      null,
      'radius_vsa',
      1800,
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
            [auth],
            IdentitySettings.create(null, null, null, null),
          ),
        ),
      ),
    } as unknown as jest.Mocked<IIdentityConfigRepository>;
    const validator = {
      validateActiveConfig: jest.fn(async () => undefined),
    } as unknown as jest.Mocked<IdentitySecretReferenceValidatorService>;
    const useCase = new UpdateIdentitySettingsUseCase(
      repository,
      new IdentityConfigMutationService(),
      validator,
      {
        decodeAccessToken: jest.fn(() => ({ sub: 'user-1', username: 'admin' })),
      } as unknown as ITokenService,
    );

    const result = await useCase.execute({
      accessToken: 'token',
      portalAuthenticationProfileId: 'auth-1',
      adminAuthenticationProfileId: 'auth-1',
    });

    expect(result.getSettings().getPortalAuthenticationProfileId()).toBe('auth-1');
    expect(result.getSettings().getAdminAuthenticationProfileId()).toBe('auth-1');
    expect(result.getSettings().getUpdatedBy()).toBe('user-1');
    expect(validator.validateActiveConfig).toHaveBeenCalledWith(result);
    expect(repository.mutate).toHaveBeenCalled();
  });

  it('preserves omitted settings fields when patching one binding', async () => {
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
    const auth = IdentityAuthenticationProfile.create(
      'auth-1',
      'Auth',
      null,
      true,
      'radius',
      'radius-1',
      null,
      'radius_vsa',
      1800,
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
            [auth],
            IdentitySettings.create('auth-1', 'auth-1', now, 'creator'),
          ),
        ),
      ),
    } as unknown as jest.Mocked<IIdentityConfigRepository>;
    const validator = {
      validateActiveConfig: jest.fn(async () => undefined),
    } as unknown as jest.Mocked<IdentitySecretReferenceValidatorService>;
    const useCase = new UpdateIdentitySettingsUseCase(
      repository,
      new IdentityConfigMutationService(),
      validator,
      {
        decodeAccessToken: jest.fn(() => ({ sub: 'user-1', username: 'admin' })),
      } as unknown as ITokenService,
    );

    const result = await useCase.execute({
      accessToken: 'token',
      portalAuthenticationProfileId: null,
    });

    expect(result.getSettings().getPortalAuthenticationProfileId()).toBeNull();
    expect(result.getSettings().getAdminAuthenticationProfileId()).toBe('auth-1');
  });

  it('throws not found when the requested authentication profile is missing', async () => {
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
    const auth = IdentityAuthenticationProfile.create(
      'auth-1',
      'Auth',
      null,
      true,
      'radius',
      'radius-1',
      null,
      'radius_vsa',
      1800,
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
            [auth],
            IdentitySettings.create('auth-1', null, now, 'creator'),
          ),
        ),
      ),
    } as unknown as jest.Mocked<IIdentityConfigRepository>;
    const validator = {
      validateActiveConfig: jest.fn(async () => undefined),
    } as unknown as jest.Mocked<IdentitySecretReferenceValidatorService>;
    const useCase = new UpdateIdentitySettingsUseCase(
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
        adminAuthenticationProfileId: 'missing-auth',
      }),
    ).rejects.toThrow(IdentityProfileNotFoundException);
  });
});
