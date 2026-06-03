import { IdentityAuthenticationProfile } from '../../../domain/entities/identity-authentication-profile.entity.js';
import { IdentityAuthenticationSequence } from '../../../domain/entities/identity-authentication-sequence.entity.js';
import { IdentityConfiguration } from '../../../domain/entities/identity-configuration.entity.js';
import { IdentityGroup } from '../../../domain/entities/identity-group.entity.js';
import { IdentitySettings } from '../../../domain/entities/identity-settings.entity.js';
import { LdapServerEndpoint } from '../../../domain/entities/ldap-server-endpoint.entity.js';
import { LdapServerProfile } from '../../../domain/entities/ldap-server-profile.entity.js';
import { RadiusServerEndpoint } from '../../../domain/entities/radius-server-endpoint.entity.js';
import { RadiusServerProfile } from '../../../domain/entities/radius-server-profile.entity.js';
import { IdentityConfigurationRecordSchema } from '../schemas/identity-config.schema.js';
import { IdentityConfigJsonMapper } from './identity-config-json.mapper.js';

const now = new Date('2026-04-30T10:00:00.000Z');
const createdBy = '00000000-0000-4000-8000-000000000001';

function config(): IdentityConfiguration {
  return IdentityConfiguration.create(
    [
      RadiusServerProfile.create(
        'radius-1',
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
        createdBy,
      ),
    ],
    [
      LdapServerProfile.create(
        'ldap-1',
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
        createdBy,
      ),
    ],
    [
      IdentityAuthenticationProfile.create(
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
        createdBy,
        [{ matchType: 'ldap_group', matchValue: 'admins', role: 'admin' }],
        {
          allowList: {
            usernames: ['alice'],
            groups: ['vpn-users'],
            includeAllAuthenticated: false,
          },
        },
      ),
    ],
    IdentitySettings.create('auth-1', null, now, null, {
      enabled: true,
      interfaceName: 'client9',
      zoneId: '00000000-0000-4000-8000-000000000010',
      bindAddress: '10.77.10.1',
      bindPort: 443,
    }),
  );
}

describe('IdentityConfigJsonMapper', () => {
  it('preserves identity config through record and domain mapping', () => {
    const record = IdentityConfigJsonMapper.toRecord(config());
    const roundtrip = IdentityConfigJsonMapper.toDomain(record);

    expect(roundtrip.getRadiusServerProfiles()[0].getSharedSecretRef()).toBe(
      'secret://identity/radius/lab',
    );
    expect(roundtrip.getLdapServerProfiles()[0].getBindPasswordRef()).toBe(
      'secret://identity/ldap/lab',
    );
    expect(roundtrip.getSettings().getPortalAuthenticationProfileId()).toBe(
      'auth-1',
    );
    expect(roundtrip.getSettings().getPortalListener().getInterfaceName()).toBe(
      'client9',
    );
    expect(roundtrip.getSettings().getPortalListener().getBindPort()).toBe(443);
    expect(roundtrip.getAuthenticationProfiles()[0].getAdminRoleMappings()).toEqual([
      { matchType: 'ldap_group', matchValue: 'admins', role: 'admin' },
    ]);
    expect(record.authentication_profiles.items[0].allowList).toEqual({
      usernames: ['alice'],
      groups: ['vpn-users'],
      includeAllAuthenticated: false,
    });
    expect(roundtrip.getAuthenticationProfiles()[0].getAllowList()).toEqual({
      usernames: ['alice'],
      groups: ['vpn-users'],
      includeAllAuthenticated: false,
    });
  });

  it('maps legacy radius profile records to one ordered endpoint', () => {
    const record = {
      ...IdentityConfigJsonMapper.emptyRecord(),
      radius_server_profiles: {
        items: [
          {
            id: 'radius-1',
            name: 'Legacy RADIUS',
            description: null,
            isActive: true,
            host: '192.168.20.30',
            port: 1812,
            sharedSecretRef: 'secret://identity/radius/legacy',
            timeoutMs: 3000,
            retries: 1,
            nasIp: null,
            nasIdentifier: null,
            calledStationId: null,
            createdAt: now.toISOString(),
            updatedAt: now.toISOString(),
            createdBy,
          },
        ],
      },
    };

    const profile = IdentityConfigJsonMapper.toDomain(record).getRadiusServerProfiles()[0];

    expect(profile.getServers()).toHaveLength(1);
    expect(profile.getServers()[0].getHost()).toBe('192.168.20.30');
    expect(profile.getServers()[0].getPriority()).toBe(1);
  });

  it('round-trips production radius endpoint records', () => {
    const profile = RadiusServerProfile.create(
      'radius-1',
      'Corp RADIUS',
      null,
      true,
      '192.168.20.30',
      1812,
      'secret://identity/radius/corp-a',
      3000,
      1,
      null,
      null,
      null,
      now,
      now,
      createdBy,
      [
        RadiusServerEndpoint.create('radius-a', 'RADIUS A', '192.168.20.30', 1812, 'secret://identity/radius/corp-a', 1, true),
        RadiusServerEndpoint.create('radius-b', 'RADIUS B', '192.168.20.31', 1812, 'secret://identity/radius/corp-b', 2, true),
      ],
      { authenticationProtocol: 'pap' },
    );

    const record = IdentityConfigJsonMapper.toRecord(
      IdentityConfiguration.create(
        [profile],
        [],
        [],
        IdentitySettings.create(null, null, now, null),
      ),
    );
    const roundtrip = IdentityConfigJsonMapper.toDomain(record).getRadiusServerProfiles()[0];

    expect(record.radius_server_profiles.items[0].servers).toHaveLength(2);
    expect('host' in record.radius_server_profiles.items[0]).toBe(false);
    expect(roundtrip.getServers().map((server) => server.getHost())).toEqual([
      '192.168.20.30',
      '192.168.20.31',
    ]);
  });

  it('maps legacy ldap profile records to one ordered endpoint', () => {
    const record = {
      ...IdentityConfigJsonMapper.emptyRecord(),
      ldap_server_profiles: {
        items: [
          {
            id: 'ldap-1',
            name: 'Legacy LDAP',
            description: null,
            isActive: true,
            host: '192.168.20.40',
            port: 389,
            tlsMode: 'disabled',
            bindDn: 'cn=admin,dc=raptorgate,dc=local',
            bindPasswordRef: 'secret://identity/ldap/legacy',
            userBaseDn: 'ou=users,dc=raptorgate,dc=local',
            userFilterAttribute: 'uid',
            groupBaseDn: 'ou=groups,dc=raptorgate,dc=local',
            groupMemberAttribute: 'memberUid',
            groupNameAttribute: 'cn',
            timeoutMs: 3000,
            cacheTtlSeconds: 300,
            createdAt: now.toISOString(),
            updatedAt: now.toISOString(),
            createdBy,
          },
        ],
      },
    };

    const profile = IdentityConfigJsonMapper.toDomain(record).getLdapServerProfiles()[0];

    expect(profile.getServers()).toHaveLength(1);
    expect(profile.getServers()[0].getHost()).toBe('192.168.20.40');
    expect(profile.getServers()[0].getPriority()).toBe(1);
    expect(profile.getGroupMapping().userBaseDn).toBe('ou=users,dc=raptorgate,dc=local');
  });

  it('round-trips authentication sequences and identity groups', () => {
    const sequence = IdentityAuthenticationSequence.create(
      'seq-1',
      'Corp fallback',
      null,
      true,
      ['auth-1'],
      true,
      false,
      now,
      now,
      createdBy,
    );
    const group = IdentityGroup.create(
      'group-1',
      'Guests',
      null,
      'local',
      null,
      [{ principal: 'alice', principalType: 'username' }],
      now,
      now,
      createdBy,
    );
    const record = IdentityConfigJsonMapper.toRecord(
      IdentityConfiguration.create(
        config().getRadiusServerProfiles(),
        config().getLdapServerProfiles(),
        config().getAuthenticationProfiles(),
        [sequence],
        [group],
        config().getSettings(),
      ),
    );
    const roundtrip = IdentityConfigJsonMapper.toDomain(record);

    expect(record.authentication_sequences.items[0].profileIds).toEqual(['auth-1']);
    expect(record.identity_groups.items[0].members).toEqual([
      { principal: 'alice', principalType: 'username' },
    ]);
    expect(roundtrip.getAuthenticationSequences()[0].getProfileIds()).toEqual(['auth-1']);
    expect(roundtrip.getIdentityGroups()[0].getMembers()).toEqual([
      { principal: 'alice', principalType: 'username' },
    ]);
  });

  it('rejects plaintext secret fields in persisted records', () => {
    const record = IdentityConfigJsonMapper.toRecord(config());
    const unsafeRecord = {
      ...record,
      radius_server_profiles: {
        items: [
          {
            ...record.radius_server_profiles.items[0],
            sharedSecret: 'radiussecret',
          },
        ],
      },
    };

    expect(() =>
      IdentityConfigurationRecordSchema.parse(unsafeRecord),
    ).toThrow();
  });
});
