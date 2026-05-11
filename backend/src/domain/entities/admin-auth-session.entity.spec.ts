import { Role } from '../enums/role.enum.js';
import { AdminAuthSession } from './admin-auth-session.entity.js';

describe('AdminAuthSession', () => {
  it('creates an active external admin session with mapped roles', () => {
    const session = AdminAuthSession.create(
      'session-1',
      'admin',
      'radius',
      'auth-1',
      'uid=admin,dc=example,dc=com',
      [Role.Admin],
      'refresh-token-hash',
      new Date('2026-05-02T11:00:00.000Z'),
      new Date('2026-05-02T10:00:00.000Z'),
      new Date('2026-05-02T10:00:00.000Z'),
      null,
    );

    expect(session.getId()).toBe('session-1');
    expect(session.getRoles()).toEqual([Role.Admin]);
    expect(session.getRefreshTokenHash()).toBe('refresh-token-hash');
    expect(session.isRevoked()).toBe(false);
  });

  it('rejects sessions without a role', () => {
    expect(() =>
      AdminAuthSession.create(
        'session-1',
        'admin',
        'radius',
        'auth-1',
        'external-admin',
        [],
        'refresh-token-hash',
        new Date('2026-05-02T11:00:00.000Z'),
        new Date('2026-05-02T10:00:00.000Z'),
        new Date('2026-05-02T10:00:00.000Z'),
        null,
      ),
    ).toThrow('admin auth session requires at least one role');
  });
});
