import { ConfigurationSnapshot } from '../../../domain/entities/configuration-snapshot.entity.js';
import { Checksum } from '../../../domain/value-objects/checksum.vo.js';
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
    Checksum.create('checksum'),
    true,
    payloadJson,
    null,
    new Date('2026-04-30T10:00:00.000Z'),
    '00000000-0000-4000-8000-000000000001',
  );
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
        updatedAt: null,
        updatedBy: null,
      },
    });
  });
});
