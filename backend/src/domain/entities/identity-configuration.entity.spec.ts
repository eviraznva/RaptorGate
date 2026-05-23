import { IdentityConfigIsInvalidException } from '../exceptions/identity-config-is-invalid.exception.js';
import { IdentityAuthenticationSequence } from './identity-authentication-sequence.entity.js';
import { IdentityAuthenticationProfile } from './identity-authentication-profile.entity.js';
import { IdentityConfiguration } from './identity-configuration.entity.js';
import { IdentityGroup } from './identity-group.entity.js';
import { IdentitySettings } from './identity-settings.entity.js';
import { LdapServerEndpoint } from './ldap-server-endpoint.entity.js';
import { LdapServerProfile } from './ldap-server-profile.entity.js';
import { RadiusServerEndpoint } from './radius-server-endpoint.entity.js';
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
    'secret://identity/radius/lab',
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

function radiusEndpoint(id: string, priority: number, isActive = true): RadiusServerEndpoint {
  return RadiusServerEndpoint.create(
    id,
    `RADIUS ${id}`,
    '192.168.20.30',
    1812,
    `secret://identity/radius/${id}`,
    priority,
    isActive,
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
    'secret://identity/ldap/lab',
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

function ldapEndpoint(id: string, priority: number, isActive = true): LdapServerEndpoint {
  return LdapServerEndpoint.create(
    id,
    `LDAP ${id}`,
    '192.168.20.40',
    389,
    priority,
    isActive,
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

  it('rejects duplicate radius endpoint priorities', () => {
    expect(() =>
      RadiusServerProfile.create(
        'radius-1',
        'Corp RADIUS',
        null,
        true,
        '192.168.20.30',
        1812,
        'secret://identity/radius/corp',
        3000,
        1,
        '192.168.20.254',
        'raptorgate',
        'portal',
        now,
        now,
        '00000000-0000-4000-8000-000000000001',
        [radiusEndpoint('radius-a', 1), radiusEndpoint('radius-b', 1)],
      ),
    ).toThrow(IdentityConfigIsInvalidException);
  });

  it('rejects unsupported radius authentication protocols', () => {
    expect(() =>
      RadiusServerProfile.create(
        'radius-1',
        'Corp RADIUS',
        null,
        true,
        '192.168.20.30',
        1812,
        'secret://identity/radius/corp',
        3000,
        1,
        '192.168.20.254',
        'raptorgate',
        'portal',
        now,
        now,
        '00000000-0000-4000-8000-000000000001',
        null,
        { authenticationProtocol: 'chap' as 'pap' },
      ),
    ).toThrow(IdentityConfigIsInvalidException);
  });

  it('rejects active radius profiles without active endpoints', () => {
    expect(() =>
      RadiusServerProfile.create(
        'radius-1',
        'Corp RADIUS',
        null,
        true,
        '192.168.20.30',
        1812,
        'secret://identity/radius/corp',
        3000,
        1,
        '192.168.20.254',
        'raptorgate',
        'portal',
        now,
        now,
        '00000000-0000-4000-8000-000000000001',
        [radiusEndpoint('radius-a', 1, false)],
      ),
    ).toThrow(IdentityConfigIsInvalidException);
  });

  it('rejects active ldap profiles without active endpoints', () => {
    expect(() =>
      LdapServerProfile.create(
        'ldap-1',
        'Corp LDAP',
        null,
        true,
        '192.168.20.40',
        389,
        'disabled',
        'cn=admin,dc=raptorgate,dc=local',
        'secret://identity/ldap/corp',
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
        [ldapEndpoint('ldap-a', 1, false)],
      ),
    ).toThrow(IdentityConfigIsInvalidException);
  });

  it('preserves production ldap profile options', () => {
    const profile = LdapServerProfile.create(
      'ldap-1',
      'Corp LDAP',
      null,
      true,
      '192.168.20.40',
      389,
      'starttls',
      'cn=admin,dc=raptorgate,dc=local',
      'secret://identity/ldap/corp',
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
      [ldapEndpoint('ldap-a', 1)],
      {
        serverType: 'active_directory',
        baseDn: 'dc=raptorgate,dc=local',
        verifyServerCertificate: true,
        certificateProfileRef: 'trust://identity/ldap/corp',
        connectTimeoutMs: 2000,
        searchTimeoutMs: 4000,
        retryIntervalSeconds: 60,
        userNameAttribute: 'sAMAccountName',
        includeGroups: ['admins', 'admins'],
        updateIntervalSeconds: 600,
      },
    );

    expect(profile.getServerType()).toBe('active_directory');
    expect(profile.getBaseDn()).toBe('dc=raptorgate,dc=local');
    expect(profile.getVerifyServerCertificate()).toBe(true);
    expect(profile.getCertificateProfileRef()).toBe('trust://identity/ldap/corp');
    expect(profile.getConnectTimeoutMs()).toBe(2000);
    expect(profile.getSearchTimeoutMs()).toBe(4000);
    expect(profile.getRetryIntervalSeconds()).toBe(60);
    expect(profile.getGroupMapping()).toEqual({
      userBaseDn: 'ou=users,dc=raptorgate,dc=local',
      userFilterAttribute: 'uid',
      userNameAttribute: 'sAMAccountName',
      groupBaseDn: 'ou=groups,dc=raptorgate,dc=local',
      groupMemberAttribute: 'memberUid',
      groupNameAttribute: 'cn',
      includeGroups: ['admins'],
      updateIntervalSeconds: 600,
    });
  });

  it('requires an ldap certificate profile when server certificate verification is enabled', () => {
    expect(() =>
      LdapServerProfile.create(
        'ldap-1',
        'Corp LDAP',
        null,
        true,
        '192.168.20.40',
        389,
        'ldaps',
        'cn=admin,dc=raptorgate,dc=local',
        'secret://identity/ldap/corp',
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
        [ldapEndpoint('ldap-a', 1)],
        {
          verifyServerCertificate: true,
          certificateProfileRef: null,
        },
      ),
    ).toThrow(IdentityConfigIsInvalidException);
  });

  it('rejects authentication sequence references to missing profiles', () => {
    const sequence = IdentityAuthenticationSequence.create(
      'seq-1',
      'Corp fallback',
      null,
      true,
      ['missing-profile'],
      true,
      false,
      now,
      now,
      '00000000-0000-4000-8000-000000000001',
    );

    expect(() =>
      IdentityConfiguration.create(
        [],
        [],
        [],
        [sequence],
        [],
        IdentitySettings.create(null, null, now, null),
      ),
    ).toThrow(IdentityConfigIsInvalidException);
  });

  it('rejects duplicate identity group names', () => {
    expect(() =>
      IdentityConfiguration.create(
        [],
        [],
        [],
        [],
        [
          IdentityGroup.create('group-1', 'Guests', null, 'local', null, [], now, now, 'tester'),
          IdentityGroup.create('group-2', 'Guests', null, 'ldap', null, [], now, now, 'tester'),
        ],
        IdentitySettings.create(null, null, now, null),
      ),
    ).toThrow(IdentityConfigIsInvalidException);
  });
});
