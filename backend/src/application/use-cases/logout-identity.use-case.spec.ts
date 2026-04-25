import { jest } from '@jest/globals';
import { IdentitySession } from '../../domain/entities/identity-session.entity.js';
import { IpAddressIsInvalidException } from '../../domain/exceptions/ip-address-is-invalid.exception.js';
import { InMemoryIdentitySessionStore } from '../../infrastructure/identity/in-memory-identity-session.store.js';
import { IpAddress } from '../../domain/value-objects/ip-address.vo.js';
import type { IIdentitySessionSyncService } from '../ports/identity-session-sync-service.interface.js';
import { LogoutIdentityUseCase } from './logout-identity.use-case.js';

describe('LogoutIdentityUseCase', () => {
  let store: InMemoryIdentitySessionStore;
  let sync: jest.Mocked<IIdentitySessionSyncService>;
  let useCase: LogoutIdentityUseCase;

  beforeEach(() => {
    store = new InMemoryIdentitySessionStore();
    sync = {
      upsertIdentitySession: jest.fn<() => Promise<void>>(),
      revokeIdentitySession: jest.fn<() => Promise<boolean>>(),
    };
    useCase = new LogoutIdentityUseCase(store, sync);
  });

  it('usuwa sesje ze store i wola revoke na firewallu', async () => {
    const now = new Date();
    await store.upsert(
      IdentitySession.create(
        'sess-1',
        'user',
        IpAddress.create('10.0.0.5'),
        now,
        new Date(now.getTime() + 60_000),
      ),
    );
    sync.revokeIdentitySession.mockResolvedValue(true);

    const result = await useCase.execute({ sourceIp: '10.0.0.5' });

    expect(result.removed).toBe(true);
    expect(await store.findBySourceIp('10.0.0.5')).toBeNull();
    expect(sync.revokeIdentitySession).toHaveBeenCalledWith('10.0.0.5');
  });

  it('toleruje brak sesji (RPC tolerancyjne wg ADR 0003)', async () => {
    sync.revokeIdentitySession.mockResolvedValue(false);

    const result = await useCase.execute({ sourceIp: '10.0.0.99' });

    expect(result.removed).toBe(false);
    expect(sync.revokeIdentitySession).toHaveBeenCalledWith('10.0.0.99');
  });

  it('zwraca removed=true gdy backend nie mial sesji ale firewall ja mial', async () => {
    sync.revokeIdentitySession.mockResolvedValue(true);

    const result = await useCase.execute({ sourceIp: '10.0.0.42' });

    expect(result.removed).toBe(true);
  });

  it('odrzuca niepoprawny sourceIp przed wolaniem firewalla', async () => {
    await expect(
      useCase.execute({ sourceIp: 'not-an-ip' }),
    ).rejects.toBeInstanceOf(IpAddressIsInvalidException);

    expect(sync.revokeIdentitySession).not.toHaveBeenCalled();
  });
});
