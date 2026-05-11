import { RefreshTokenIsInvalidException } from '../../domain/exceptions/refresh-token-is-invalid.exception.js';
import { AdminAuthSession } from '../../domain/entities/admin-auth-session.entity.js';
import { Role } from '../../domain/enums/role.enum.js';
import type { IAdminAuthSessionRepository } from '../../domain/repositories/admin-auth-session.repository.js';
import type { IUserRepository } from '../../domain/repositories/user.repository.js';
import type { IPasswordHasher } from '../ports/passowrd-hasher.interface.js';
import type { ITokenService } from '../ports/token-service.interface.js';
import { RefreshTokenUseCase } from './refresh-token.use-case.js';

describe('RefreshTokenUseCase external admin sessions', () => {
  it('rotates an external admin refresh token on every refresh', async () => {
    const session = AdminAuthSession.create(
      'session-1',
      'admin',
      'radius',
      'auth-1',
      'external-admin',
      [Role.Admin],
      'refresh-token-hash',
      new Date(Date.now() + 60 * 60 * 1000),
      new Date(),
      new Date(),
      null,
    );
    const tokenService = {
      verifyAccessToken: jest.fn(async () => ({
        sub: 'session-1',
        username: 'admin',
        principalType: 'external_admin',
      })),
      decodeAccessToken: jest.fn(() => ({
        sub: 'session-1',
        username: 'admin',
        principalType: 'external_admin',
      })),
      generateAccessToken: jest.fn(),
      generateTokenPair: jest.fn(async () => ({
        accessToken: 'new-access',
        refreshToken: 'new-refresh',
      })),
    } as unknown as jest.Mocked<ITokenService>;
    const passwordHasher = {
      compare: jest.fn(async () => true),
      hash: jest.fn(async () => 'new-refresh-hash'),
    } as unknown as jest.Mocked<IPasswordHasher>;
    const userRepository = {} as unknown as IUserRepository;
    const adminSessionRepository = {
      findById: jest.fn(async () => session),
      save: jest.fn(),
      revoke: jest.fn(),
    } as unknown as jest.Mocked<IAdminAuthSessionRepository>;
    const useCase = new RefreshTokenUseCase(
      tokenService,
      userRepository,
      adminSessionRepository,
      passwordHasher,
    );

    const result = await useCase.execute({
      accessToken: 'old-access',
      refreshToken: 'refresh-token',
    });

    expect(result.accessToken).toBe('new-access');
    expect(result.refreshToken).toBe('new-refresh');
    expect(passwordHasher.compare).toHaveBeenCalledWith('refresh-token', 'refresh-token-hash');
    expect(session.getRefreshTokenHash()).toBe('new-refresh-hash');
    expect(adminSessionRepository.save).toHaveBeenCalledWith(session);
  });

  it('rejects a revoked external admin session', async () => {
    const session = AdminAuthSession.create(
      'session-1',
      'admin',
      'radius',
      'auth-1',
      'external-admin',
      [Role.Admin],
      'refresh-token-hash',
      new Date(Date.now() + 60 * 60 * 1000),
      new Date(),
      new Date(),
      new Date(),
    );
    const tokenService = {
      verifyAccessToken: jest.fn(async () => ({
        sub: 'session-1',
        username: 'admin',
        principalType: 'external_admin',
      })),
      decodeAccessToken: jest.fn(() => ({
        sub: 'session-1',
        username: 'admin',
        principalType: 'external_admin',
      })),
    } as unknown as jest.Mocked<ITokenService>;
    const useCase = new RefreshTokenUseCase(
      tokenService,
      {} as unknown as IUserRepository,
      {
        findById: jest.fn(async () => session),
      } as unknown as IAdminAuthSessionRepository,
      {
        compare: jest.fn(async () => true),
      } as unknown as IPasswordHasher,
    );

    await expect(
      useCase.execute({ accessToken: 'old-access', refreshToken: 'refresh-token' }),
    ).rejects.toBeInstanceOf(RefreshTokenIsInvalidException);
  });
});
