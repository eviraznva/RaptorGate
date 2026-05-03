import { IdentityConfigIsInvalidException } from '../exceptions/identity-config-is-invalid.exception.js';
import { IdentitySettings } from './identity-settings.entity.js';

describe('IdentitySettings', () => {
  it('accepts a valid portal listener configuration', () => {
    const settings = IdentitySettings.create(null, null, null, null, {
      enabled: true,
      interfaceName: 'eth1.20',
      zoneId: '11111111-1111-4111-8111-111111111111',
      bindAddress: '192.0.2.10',
      bindPort: 443,
    });

    expect(settings.getPortalListener().getBindAddress()).toBe('192.0.2.10');
  });

  it('rejects an invalid portal listener bind address', () => {
    expect(() =>
      IdentitySettings.create(null, null, null, null, {
        enabled: true,
        interfaceName: 'eth1',
        zoneId: '11111111-1111-4111-8111-111111111111',
        bindAddress: 'not-an-ip',
        bindPort: 443,
      }),
    ).toThrow(IdentityConfigIsInvalidException);
  });

  it('rejects an invalid portal listener zone id', () => {
    expect(() =>
      IdentitySettings.create(null, null, null, null, {
        enabled: true,
        interfaceName: 'eth1',
        zoneId: 'clients',
        bindAddress: '192.0.2.10',
        bindPort: 443,
      }),
    ).toThrow(IdentityConfigIsInvalidException);
  });
});
