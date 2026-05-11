import { jest } from '@jest/globals';
import { IdentityConfiguration } from '../../domain/entities/identity-configuration.entity.js';
import { IdentitySettings } from '../../domain/entities/identity-settings.entity.js';
import { RadiusServerProfile } from '../../domain/entities/radius-server-profile.entity.js';
import type { IIdentityConfigRepository } from '../../domain/repositories/identity-config.repository.js';
import { SecretValue } from '../../domain/value-objects/secret-value.vo.js';
import type {
  IRadiusAuthenticator,
  RadiusAuthResult,
} from '../ports/radius-authenticator.interface.js';
import type { ISecretResolverService } from '../ports/secret-resolver.service.js';
import type { ITokenService } from '../ports/token-service.interface.js';
import { TestRadiusProfileUseCase } from './test-radius-profile.use-case.js';

describe('TestRadiusProfileUseCase', () => {
  it('tests the selected radius profile with resolved secret and profile transport settings', async () => {
    const now = new Date('2026-05-01T10:00:00.000Z');
    const radius = RadiusServerProfile.create(
      'radius-1',
      'Radius',
      null,
      true,
      '10.0.0.10',
      1812,
      'secret://identity/radius/default',
      4000,
      2,
      '192.0.2.1',
      'raptorgate',
      'portal',
      now,
      now,
      'creator',
    );
    const repository = {
      find: jest.fn(async () =>
        IdentityConfiguration.create(
          [radius],
          [],
          [],
          IdentitySettings.create(null, null, null, null),
        ),
      ),
    } as unknown as jest.Mocked<IIdentityConfigRepository>;
    const secretResolver = {
      resolve: jest.fn(async () => SecretValue.create('radius-secret')),
    } as unknown as jest.Mocked<ISecretResolverService>;
    const radiusAuthenticator = {
      authenticate: jest.fn(async () => ({ kind: 'accept', groups: ['admins'] })),
    } as unknown as jest.Mocked<IRadiusAuthenticator>;
    const useCase = new TestRadiusProfileUseCase(
      repository,
      secretResolver,
      radiusAuthenticator,
      {
        decodeAccessToken: jest.fn(() => ({ sub: 'user-1', username: 'admin' })),
      } as unknown as ITokenService,
    );

    const result = await useCase.execute({
      accessToken: 'token',
      id: 'radius-1',
      username: 'admin',
      password: 'password',
      callingStationId: '198.51.100.10',
    });

    expect(result.result).toBe('accept');
    expect(result.groups).toEqual(['admins']);
    expect(radiusAuthenticator.authenticate).toHaveBeenCalledWith({
      username: 'admin',
      password: 'password',
      callingStationId: '198.51.100.10',
      server: {
        host: '10.0.0.10',
        port: 1812,
        secret: 'radius-secret',
        timeoutMs: 4000,
        retries: 2,
        nasIp: '192.0.2.1',
        nasIdentifier: 'raptorgate',
        calledStationId: 'portal',
      },
    });
  });

  it('maps radius reject to diagnostic response', async () => {
    const { useCase } = makeUseCaseWithRadiusResult({
      kind: 'reject',
      reason: 'Access-Reject',
    });

    const result = await useCase.execute({
      accessToken: 'token',
      id: 'radius-1',
      username: 'admin',
      password: 'password',
      callingStationId: '198.51.100.10',
    });

    expect(result.result).toBe('reject');
    expect(result.message).toBe('Access-Reject');
  });

  it('maps radius timeout to diagnostic response', async () => {
    const { useCase } = makeUseCaseWithRadiusResult({ kind: 'timeout' });

    const result = await useCase.execute({
      accessToken: 'token',
      id: 'radius-1',
      username: 'admin',
      password: 'password',
      callingStationId: '198.51.100.10',
    });

    expect(result.result).toBe('timeout');
    expect(result.message).toBe('RADIUS request timed out');
  });

  it('maps radius error to diagnostic response', async () => {
    const { useCase } = makeUseCaseWithRadiusResult({
      kind: 'error',
      message: 'socket error',
    });

    const result = await useCase.execute({
      accessToken: 'token',
      id: 'radius-1',
      username: 'admin',
      password: 'password',
      callingStationId: '198.51.100.10',
    });

    expect(result.result).toBe('error');
    expect(result.message).toBe('socket error');
  });
});

function makeUseCaseWithRadiusResult(result: RadiusAuthResult): {
  useCase: TestRadiusProfileUseCase;
} {
  const now = new Date('2026-05-01T10:00:00.000Z');
  const radius = RadiusServerProfile.create(
    'radius-1',
    'Radius',
    null,
    true,
    '10.0.0.10',
    1812,
    'secret://identity/radius/default',
    4000,
    2,
    '192.0.2.1',
    'raptorgate',
    'portal',
    now,
    now,
    'creator',
  );
  const repository = {
    find: jest.fn(async () =>
      IdentityConfiguration.create(
        [radius],
        [],
        [],
        IdentitySettings.create(null, null, null, null),
      ),
    ),
  } as unknown as jest.Mocked<IIdentityConfigRepository>;
  const secretResolver = {
    resolve: jest.fn(async () => SecretValue.create('radius-secret')),
  } as unknown as jest.Mocked<ISecretResolverService>;
  const radiusAuthenticator = {
    authenticate: jest.fn(async () => result),
  } as unknown as jest.Mocked<IRadiusAuthenticator>;

  return {
    useCase: new TestRadiusProfileUseCase(
      repository,
      secretResolver,
      radiusAuthenticator,
      {
        decodeAccessToken: jest.fn(() => ({ sub: 'user-1', username: 'admin' })),
      } as unknown as ITokenService,
    ),
  };
}
