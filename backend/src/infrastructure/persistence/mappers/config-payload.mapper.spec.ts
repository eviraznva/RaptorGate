import { ConfigurationSnapshot } from '../../../domain/entities/configuration-snapshot.entity.js';
import { IdentityAuthenticationProfile } from '../../../domain/entities/identity-authentication-profile.entity.js';
import { IdentitySettings } from '../../../domain/entities/identity-settings.entity.js';
import { LdapServerProfile } from '../../../domain/entities/ldap-server-profile.entity.js';
import { RadiusServerProfile } from '../../../domain/entities/radius-server-profile.entity.js';
import { Checksum } from '../../../domain/value-objects/checksum.vo.js';
import type { ConfigSnapshotPayload } from '../../../domain/value-objects/config-snapshot-payload.interface.js';
import { SnapshotType } from '../../../domain/value-objects/snapshot-type.vo.js';
import {
  mapConfigBundlePayloadToDomain,
  mapConfigSnapshotToPayloadRecord,
} from './config-payload.mapper.js';

const emptyBundle = {
  rules: { items: [] },
  zones: { items: [] },
  zone_interfaces: { items: [] },
  zone_pairs: { items: [] },
  nat_rules: { items: [] },
  dns_blacklist: { items: [] },
  ssl_bypass_list: { items: [] },
  ips_signatures: { items: [] },
  ml_model: null,
  firewall_certificates: { items: [] },
  users: { items: [] },
};

function snapshot(payloadJson: unknown): ConfigurationSnapshot {
  return ConfigurationSnapshot.create(
    '00000000-0000-4000-8000-000000000010',
    1,
    SnapshotType.create('manual_import'),
    Checksum.create('0'.repeat(64)),
    true,
    payloadJson,
    null,
    new Date('2026-04-30T10:00:00.000Z'),
    '00000000-0000-4000-8000-000000000001',
  );
}

function snapshotFromPayload(payload: ConfigSnapshotPayload): ConfigurationSnapshot {
  return snapshot(payload);
}

function snapshotFromRecord(record: unknown): ConfigurationSnapshot {
  return snapshot(JSON.stringify(record));
}

function configPayloadWithIdentity(input: {
  radiusName: string;
  ldapName: string;
  authName: string;
  now: Date;
}): ConfigSnapshotPayload {
  return {
    bundle: {
      ...emptyBundle,
      identity_config: {
        radius_server_profiles: {
          items: [
            RadiusServerProfile.create(
              'radius-1',
              input.radiusName,
              null,
              true,
              '192.0.2.10',
              1812,
              'secret://identity/radius/corp',
              3000,
              2,
              null,
              'raptorgate',
              null,
              input.now,
              input.now,
              'tester',
            ),
          ],
        },
        ldap_server_profiles: {
          items: [
            LdapServerProfile.create(
              'ldap-1',
              input.ldapName,
              null,
              true,
              'ldap.example.test',
              389,
              'disabled',
              'cn=admin,dc=example,dc=test',
              'secret://identity/ldap/corp',
              'ou=users,dc=example,dc=test',
              'uid',
              'ou=groups,dc=example,dc=test',
              'memberUid',
              'cn',
              3000,
              300,
              input.now,
              input.now,
              'tester',
            ),
          ],
        },
        authentication_profiles: {
          items: [
            IdentityAuthenticationProfile.create(
              'auth-1',
              input.authName,
              null,
              true,
              'radius',
              'radius-1',
              'ldap-1',
              'ldap',
              3600,
              input.now,
              input.now,
              'tester',
            ),
          ],
        },
        settings: IdentitySettings.create('auth-1', null, input.now, 'tester'),
      },
    },
  };
}

describe('config payload mapper identity config', () => {
  it('defaults old snapshots without identity_config to an empty identity config', () => {
    const mapped = mapConfigBundlePayloadToDomain(
      snapshot(JSON.stringify({ bundle: emptyBundle })),
    );

    expect(mapped.bundle.identity_config.radius_server_profiles.items).toEqual(
      [],
    );
    expect(
      mapped.bundle.identity_config.settings.getPortalAuthenticationProfileId(),
    ).toBeNull();
  });

  it('exports identity_config records in config snapshots', () => {
    const domainSnapshot = snapshot(
      mapConfigBundlePayloadToDomain(
        snapshot(JSON.stringify({ bundle: emptyBundle })),
      ),
    );

    const record = mapConfigSnapshotToPayloadRecord(domainSnapshot);

    expect(record.bundle.identity_config).toEqual({
      radius_server_profiles: { items: [] },
      ldap_server_profiles: { items: [] },
      authentication_profiles: { items: [] },
      settings: {
        portalAuthenticationProfileId: null,
        adminAuthenticationProfileId: null,
        portalListener: {
          enabled: false,
          interfaceName: null,
          zoneId: null,
          bindAddress: null,
          bindPort: 443,
        },
        updatedAt: null,
        updatedBy: null,
      },
    });
  });

  it('preserves production identity_config through durable snapshot mapping', () => {
    const now = new Date('2026-05-23T10:00:00.000Z');
    const payload = configPayloadWithIdentity({
      radiusName: 'corp-radius',
      ldapName: 'corp-ad',
      authName: 'corp-portal',
      now,
    });

    const record = mapConfigSnapshotToPayloadRecord(snapshotFromPayload(payload));
    const mapped = mapConfigBundlePayloadToDomain(snapshotFromRecord(record));

    expect(
      mapped.bundle.identity_config.radius_server_profiles.items[0].getName(),
    ).toBe('corp-radius');
    expect(
      mapped.bundle.identity_config.ldap_server_profiles.items[0].getName(),
    ).toBe('corp-ad');
    expect(
      mapped.bundle.identity_config.authentication_profiles.items[0].getName(),
    ).toBe('corp-portal');
  });
});
