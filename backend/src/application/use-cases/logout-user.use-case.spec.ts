import { Role } from '../../domain/enums/role.enum.js';
import type { IAdminAuthSessionRepository } from '../../domain/repositories/admin-auth-session.repository.js';
import type { IUserRepository } from '../../domain/repositories/user.repository.js';
import type { ITokenService } from '../ports/token-service.interface.js';
import { LogoutUserUseCase } from './logout-user.use-case.js';

describe('LogoutUserUseCase external admin sessions', () => {
  it('revokes external admin sessions without touching local users', async () => {
    const tokenService = {
      verifyAccessToken: jest.fn(async () => ({
        sub: 'session-1',
        username: 'admin',
        principalType: 'external_admin',
        roles: [Role.Admin],
      })),
      decodeAccessToken: jest.fn(() => ({
        sub: 'session-1',
        username: 'admin',
        principalType: 'external_admin',
        roles: [Role.Admin],
      })),
    } as unknown as jest.Mocked<ITokenService>;
    const userRepository = {
      findById: jest.fn(),
    } as unknown as jest.Mocked<IUserRepository>;
    const adminSessionRepository = {
      revoke: jest.fn(),
    } as unknown as jest.Mocked<IAdminAuthSessionRepository>;
    const useCase = new LogoutUserUseCase(
      userRepository,
      tokenService,
      adminSessionRepository,
    );

    await useCase.execute({ accessToken: 'external-access' });

    expect(adminSessionRepository.revoke).toHaveBeenCalledWith(
      'session-1',
      expect.any(Date),
    );
    expect(userRepository.findById).not.toHaveBeenCalled();
  });
});
