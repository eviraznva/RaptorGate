import { IdentityAuthenticationProfile } from '../../../domain/entities/identity-authentication-profile.entity.js';
import { IdentityConfiguration } from '../../../domain/entities/identity-configuration.entity.js';
import { IdentitySettings } from '../../../domain/entities/identity-settings.entity.js';
import { LdapServerProfile } from '../../../domain/entities/ldap-server-profile.entity.js';
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
        'secret:radius/lab',
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
      ),
    ],
    IdentitySettings.create('auth-1', null, now, null),
  );
}

describe('IdentityConfigJsonMapper', () => {
  it('preserves identity config through record and domain mapping', () => {
    const record = IdentityConfigJsonMapper.toRecord(config());
    const roundtrip = IdentityConfigJsonMapper.toDomain(record);

    expect(roundtrip.getRadiusServerProfiles()[0].getSharedSecretRef()).toBe(
      'secret:radius/lab',
    );
    expect(roundtrip.getLdapServerProfiles()[0].getBindPasswordRef()).toBe(
      'secret:ldap/lab',
    );
    expect(roundtrip.getSettings().getPortalAuthenticationProfileId()).toBe(
      'auth-1',
    );
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
