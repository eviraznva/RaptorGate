import { RevokeIdentitySessionUseCase } from './revoke-identity-session.use-case.js';
import type { LogoutIdentityUseCase } from './logout-identity.use-case.js';
import type { IIdentitySessionStore } from '../../domain/repositories/identity-session-store.js';
import { IdentitySession } from '../../domain/entities/identity-session.entity.js';
import { IpAddress } from '../../domain/value-objects/ip-address.vo.js';

describe('RevokeIdentitySessionUseCase', () => {
  it('revokes a runtime identity session by source IP', async () => {
    const logoutIdentityUseCase = {
      execute: jest.fn(async () => ({ removed: true })),
    } as unknown as jest.Mocked<LogoutIdentityUseCase>;
    const store = {
      listAll: jest.fn(),
    } as unknown as jest.Mocked<IIdentitySessionStore>;
    const useCase = new RevokeIdentitySessionUseCase(logoutIdentityUseCase, store);

    const result = await useCase.execute({ sourceIp: '10.0.0.10' });

    expect(result).toEqual({ removed: true });
    expect(logoutIdentityUseCase.execute).toHaveBeenCalledWith({
      sourceIp: '10.0.0.10',
    });
  });

  it('revokes a runtime identity session by session ID', async () => {
    const logoutIdentityUseCase = {
      execute: jest.fn(async () => ({ removed: true })),
    } as unknown as jest.Mocked<LogoutIdentityUseCase>;
    const store = {
      listAll: jest.fn(async () => [
        IdentitySession.create(
          'sess-1',
          'user',
          IpAddress.create('10.0.0.10'),
          new Date('2026-05-02T10:00:00.000Z'),
          new Date('2026-05-02T10:30:00.000Z'),
        ),
      ]),
    } as unknown as jest.Mocked<IIdentitySessionStore>;
    const useCase = new RevokeIdentitySessionUseCase(logoutIdentityUseCase, store);

    const result = await useCase.execute({ sessionId: 'sess-1' });

    expect(result).toEqual({ removed: true });
    expect(logoutIdentityUseCase.execute).toHaveBeenCalledWith({
      sourceIp: '10.0.0.10',
    });
  });

  it('does not revoke a stale session ID', async () => {
    const logoutIdentityUseCase = {
      execute: jest.fn(async () => ({ removed: true })),
    } as unknown as jest.Mocked<LogoutIdentityUseCase>;
    const store = {
      listAll: jest.fn(async () => [
        IdentitySession.create(
          'sess-2',
          'user',
          IpAddress.create('10.0.0.10'),
          new Date('2026-05-02T10:00:00.000Z'),
          new Date('2026-05-02T10:30:00.000Z'),
        ),
      ]),
    } as unknown as jest.Mocked<IIdentitySessionStore>;
    const useCase = new RevokeIdentitySessionUseCase(logoutIdentityUseCase, store);

    const result = await useCase.execute({ sessionId: 'sess-1', sourceIp: '10.0.0.10' });

    expect(result).toEqual({ removed: false });
    expect(logoutIdentityUseCase.execute).not.toHaveBeenCalled();
  });
});
