import { InvalidCredentialsException } from '../../domain/exceptions/invalid-credentials.exception.js';
import { AuthenticationMisconfiguredException } from '../../domain/exceptions/authentication-misconfigured.exception.js';
import { AuthenticationUnavailableException } from '../../domain/exceptions/authentication-unavailable.exception.js';
import { User } from '../../domain/entities/user.entity.js';
import { Role } from '../../domain/enums/role.enum.js';
import type { IAdminAuthSessionRepository } from '../../domain/repositories/admin-auth-session.repository.js';
import type { IUserRepository } from '../../domain/repositories/user.repository.js';
import type { IPasswordHasher } from '../ports/passowrd-hasher.interface.js';
import type { IRecoveryTokenService } from '../ports/recovery-token-service.interface.js';
import type { ITokenService } from '../ports/token-service.interface.js';
import type { AdminAuthorizationService } from '../services/admin-authorization.service.js';
import type { AuthenticationEngineService } from '../services/authentication-engine.service.js';
import { LoginUserUseCase } from './login-user.use-case.js';

describe('LoginUserUseCase external admin authentication', () => {
  const now = new Date('2026-01-01T00:00:00.000Z');
  let adminAuthSessionRepository: jest.Mocked<IAdminAuthSessionRepository>;

  function user(): User {
    return User.create(
      'user-1',
      'admin',
      'hash',
      null,
      null,
      null,
      false,
      false,
      now,
      now,
      [],
    );
  }

  function makeUseCase(input: {
    foundUser: User | null;
    passwordValid: boolean;
    engineResult: Awaited<ReturnType<AuthenticationEngineService['authenticate']>>;
    authorizationResult?: Awaited<ReturnType<AdminAuthorizationService['authorize']>>;
  }): LoginUserUseCase {
    const userRepository = {
      findByUsername: jest.fn(async () => input.foundUser),
      setRefreshToken: jest.fn(),
      save: jest.fn(),
    } as unknown as jest.Mocked<IUserRepository>;
    const passwordHasher = {
      compare: jest.fn(async () => input.passwordValid),
      hash: jest.fn(async () => 'refresh-hash'),
    } as unknown as jest.Mocked<IPasswordHasher>;
    const tokenService = {
      generateTokenPair: jest.fn(async () => ({
        accessToken: 'access',
        refreshToken: 'refresh',
      })),
    } as unknown as jest.Mocked<ITokenService>;
    const recoveryTokenService = {
      createRecoveryToken: jest.fn(),
    } as unknown as jest.Mocked<IRecoveryTokenService>;
    const authenticationEngine = {
      authenticate: jest.fn(async () => input.engineResult),
    } as unknown as jest.Mocked<AuthenticationEngineService>;
    const adminAuthorization = {
      authorize: jest.fn(async () =>
        input.authorizationResult ?? {
          kind: 'authorized',
          role: Role.Admin,
          matchedBy: 'ldap_group',
          matchedValue: 'admins',
        },
      ),
    } as unknown as jest.Mocked<AdminAuthorizationService>;
    adminAuthSessionRepository = {
      save: jest.fn(),
    } as unknown as jest.Mocked<IAdminAuthSessionRepository>;

    return new LoginUserUseCase(
      userRepository,
      passwordHasher,
      tokenService,
      recoveryTokenService,
      authenticationEngine,
      adminAuthorization,
      adminAuthSessionRepository,
    );
  }

  it('keeps local break-glass login working when external authentication is unavailable', async () => {
    const useCase = makeUseCase({
      foundUser: user(),
      passwordValid: true,
      engineResult: {
        kind: 'unavailable',
        provider: 'radius',
        message: 'RADIUS timeout',
        profileId: 'auth-1',
      },
    });

    const result = await useCase.execute({ username: 'admin', password: 'local' });

    expect(result.accessToken).toBe('access');
    expect(result.refreshToken).toBe('refresh');
  });

  it('allows an existing local admin after external RADIUS accept', async () => {
    const useCase = makeUseCase({
      foundUser: user(),
      passwordValid: false,
      engineResult: {
        kind: 'accept',
        provider: 'radius',
        username: 'admin',
        groups: [],
        groupSource: 'ldap',
        externalId: 'admin',
        sessionTtlSeconds: 1800,
        nasIp: '192.0.2.1',
        calledStationId: 'raptorgate',
        profileId: 'auth-1',
      },
    });

    const result = await useCase.execute({ username: 'admin', password: 'radius' });

    expect(result.accessToken).toBe('access');
  });

  it('allows mapped external admin without a local user', async () => {
    const useCase = makeUseCase({
      foundUser: null,
      passwordValid: false,
      engineResult: {
        kind: 'accept',
        provider: 'radius',
        username: 'admin',
        groups: ['admins'],
        groupSource: 'ldap',
        externalId: 'admin',
        sessionTtlSeconds: 1800,
        nasIp: '192.0.2.1',
        calledStationId: 'raptorgate',
        profileId: 'auth-1',
      },
    });

    const result = await useCase.execute({ username: 'admin', password: 'radius' });

    expect(result.accessToken).toBe('access');
    expect(adminAuthSessionRepository.save).toHaveBeenCalled();
    const session = adminAuthSessionRepository.save.mock.calls[0][0];
    expect(session.getRefreshTokenHash()).toBe('refresh-hash');
  });

  it('rejects external admin accept without a role mapping', async () => {
    const useCase = makeUseCase({
      foundUser: null,
      passwordValid: false,
      engineResult: {
        kind: 'accept',
        provider: 'radius',
        username: 'admin',
        groups: ['users'],
        groupSource: 'ldap',
        externalId: 'admin',
        sessionTtlSeconds: 1800,
        nasIp: '192.0.2.1',
        calledStationId: 'raptorgate',
        profileId: 'auth-1',
      },
      authorizationResult: { kind: 'denied', reason: 'admin role mapping not found' },
    });

    await expect(
      useCase.execute({ username: 'admin', password: 'radius' }),
    ).rejects.toBeInstanceOf(InvalidCredentialsException);
  });

  it('keeps anti-enumeration when external provider is unavailable for an unknown local user', async () => {
    const useCase = makeUseCase({
      foundUser: null,
      passwordValid: false,
      engineResult: {
        kind: 'unavailable',
        provider: 'radius',
        message: 'RADIUS timeout',
        profileId: 'auth-1',
      },
    });

    await expect(
      useCase.execute({ username: 'missing', password: 'radius' }),
    ).rejects.toBeInstanceOf(InvalidCredentialsException);
  });

  it('surfaces provider unavailability when the local user exists but local password failed', async () => {
    const useCase = makeUseCase({
      foundUser: user(),
      passwordValid: false,
      engineResult: {
        kind: 'timeout',
        provider: 'radius',
        message: 'RADIUS timeout',
        profileId: 'auth-1',
      },
    });

    await expect(
      useCase.execute({ username: 'admin', password: 'radius' }),
    ).rejects.toBeInstanceOf(AuthenticationUnavailableException);
  });

  it('surfaces authentication misconfiguration for an existing local user', async () => {
    const useCase = makeUseCase({
      foundUser: user(),
      passwordValid: false,
      engineResult: {
        kind: 'misconfigured',
        message: 'admin authentication profile is inactive',
        profileId: 'auth-1',
      },
    });

    await expect(
      useCase.execute({ username: 'admin', password: 'radius' }),
    ).rejects.toBeInstanceOf(AuthenticationMisconfiguredException);
  });
});
