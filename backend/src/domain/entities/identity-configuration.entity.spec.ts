import { IdentityConfigIsInvalidException } from '../exceptions/identity-config-is-invalid.exception.js';
import { IdentityAuthenticationProfile } from './identity-authentication-profile.entity.js';
import { IdentityConfiguration } from './identity-configuration.entity.js';
import { IdentitySettings } from './identity-settings.entity.js';
import { LdapServerProfile } from './ldap-server-profile.entity.js';
import { RadiusServerProfile } from './radius-server-profile.entity.js';

const now = new Date('2026-04-30T10:00:00.000Z');

function radiusProfile(id = 'radius-1'): RadiusServerProfile {
  return RadiusServerProfile.create(
    id,
    'Lab RADIUS',
    null,
    true,
    '192.168.20.30',
    1812,
    'secret:radius/lab',
    3000,
    1,
    '192.168.20.254',
    'raptorgate',
    'portal',
    now,
    now,
    '00000000-0000-4000-8000-000000000001',
  );
}

function ldapProfile(id = 'ldap-1'): LdapServerProfile {
  return LdapServerProfile.create(
    id,
    'Lab LDAP',
    null,
    true,
    '192.168.20.40',
    389,
    'disabled',
    'cn=admin,dc=raptorgate,dc=local',
    'secret:ldap/lab',
    'ou=users,dc=raptorgate,dc=local',
    'uid',
    'ou=groups,dc=raptorgate,dc=local',
    'memberUid',
    'cn',
    3000,
    300,
    now,
    now,
    '00000000-0000-4000-8000-000000000001',
  );
}

describe('IdentityConfiguration', () => {
  it('accepts authentication profiles with valid provider references', () => {
    const authProfile = IdentityAuthenticationProfile.create(
      'auth-1',
      'Portal auth',
      null,
      true,
      'radius',
      'radius-1',
      'ldap-1',
      'ldap',
      1800,
      now,
      now,
      '00000000-0000-4000-8000-000000000001',
    );

    const config = IdentityConfiguration.create(
      [radiusProfile()],
      [ldapProfile()],
      [authProfile],
      IdentitySettings.create('auth-1', null, now, null),
    );

    expect(config.getAuthenticationProfiles()[0].getRadiusProfileId()).toBe(
      'radius-1',
    );
    expect(config.getSettings().getPortalAuthenticationProfileId()).toBe(
      'auth-1',
    );
  });

  it('rejects a radius authentication profile without a radius profile id', () => {
    expect(() =>
      IdentityAuthenticationProfile.create(
        'auth-1',
        'Broken auth',
        null,
        true,
        'radius',
        null,
        null,
        'none',
        1800,
        now,
        now,
        '00000000-0000-4000-8000-000000000001',
      ),
    ).toThrow(IdentityConfigIsInvalidException);
  });

  it('rejects authentication profiles that reference missing provider profiles', () => {
    const authProfile = IdentityAuthenticationProfile.create(
      'auth-1',
      'Portal auth',
      null,
      true,
      'radius',
      'missing-radius',
      null,
      'none',
      1800,
      now,
      now,
      '00000000-0000-4000-8000-000000000001',
    );

    expect(() =>
      IdentityConfiguration.create(
        [radiusProfile()],
        [],
        [authProfile],
        IdentitySettings.create('auth-1', null, now, null),
      ),
    ).toThrow(IdentityConfigIsInvalidException);
  });

  it('rejects settings that reference a missing authentication profile', () => {
    expect(() =>
      IdentityConfiguration.create(
        [],
        [],
        [],
        IdentitySettings.create('missing-auth', null, now, null),
      ),
    ).toThrow(IdentityConfigIsInvalidException);
  });
});
