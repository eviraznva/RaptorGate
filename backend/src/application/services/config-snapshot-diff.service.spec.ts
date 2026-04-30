import { ConfigSnapshotDiffService } from './config-snapshot-diff.service.js';

describe('ConfigSnapshotDiffService identity secrets', () => {
  it('redacts identity secret references in diffs', () => {
    const service = new ConfigSnapshotDiffService();
    const basePayload = {
      bundle: {
        identity_config: {
          radius_server_profiles: {
            items: [
              {
                id: 'radius-1',
                sharedSecretRef: 'env:RADIUS_SECRET',
              },
            ],
          },
          ldap_server_profiles: {
            items: [
              {
                id: 'ldap-1',
                bindPasswordRef: 'env:IDENTITY_LDAP_BIND_PASSWORD',
              },
            ],
          },
          authentication_profiles: { items: [] },
          settings: {},
        },
      },
    } as any;
    const targetPayload = {
      bundle: {
        identity_config: {
          radius_server_profiles: {
            items: [
              {
                id: 'radius-1',
                sharedSecretRef: 'secret://identity/radius/prod',
              },
            ],
          },
          ldap_server_profiles: {
            items: [
              {
                id: 'ldap-1',
                bindPasswordRef: 'secret://identity/ldap/prod',
              },
            ],
          },
          authentication_profiles: { items: [] },
          settings: {},
        },
      },
    } as any;

    const result = service.diff(basePayload, targetPayload);

    expect(JSON.stringify(result.changes)).not.toContain('RADIUS_SECRET');
    expect(JSON.stringify(result.changes)).not.toContain(
      'IDENTITY_LDAP_BIND_PASSWORD',
    );
    expect(JSON.stringify(result.changes)).not.toContain(
      'secret://identity/radius/prod',
    );
  });
});
