import { IdentityConfigIsInvalidException } from '../exceptions/identity-config-is-invalid.exception.js';
import { IdentityAuthenticationProfile } from './identity-authentication-profile.entity.js';

const now = new Date('2026-05-02T10:00:00.000Z');

describe('IdentityAuthenticationProfile admin role mappings', () => {
  it('preserves ordered admin role mappings', () => {
    const profile = IdentityAuthenticationProfile.create(
      'auth-1',
      'Admin RADIUS',
      null,
      true,
      'radius',
      'radius-1',
      'ldap-1',
      'ldap',
      1800,
      now,
      now,
      'creator',
      [
        { matchType: 'ldap_group', matchValue: 'admins', role: 'admin' },
        { matchType: 'username', matchValue: 'breakglass', role: 'super_admin' },
      ],
    );

    expect(profile.getAdminRoleMappings()).toEqual([
      { matchType: 'ldap_group', matchValue: 'admins', role: 'admin' },
      { matchType: 'username', matchValue: 'breakglass', role: 'super_admin' },
    ]);
  });

  it('rejects blank mapping values', () => {
    expect(() =>
      IdentityAuthenticationProfile.create(
        'auth-1',
        'Admin RADIUS',
        null,
        true,
        'radius',
        'radius-1',
        'ldap-1',
        'ldap',
        1800,
        now,
        now,
        'creator',
        [{ matchType: 'ldap_group', matchValue: ' ', role: 'admin' }],
      ),
    ).toThrow(IdentityConfigIsInvalidException);
  });
});
