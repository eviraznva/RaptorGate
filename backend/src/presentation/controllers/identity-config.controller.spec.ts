import { IdentityConfiguration } from '../../domain/entities/identity-configuration.entity.js';
import { IdentityConfigController } from './identity-config.controller.js';

describe('IdentityConfigController', () => {
  it('returns identity config from the read use case', async () => {
    const controller = new IdentityConfigController(
      { execute: async () => IdentityConfiguration.empty() } as any,
      {} as any,
      {} as any,
      {} as any,
      {} as any,
      {} as any,
      {} as any,
      {} as any,
      {} as any,
      {} as any,
      {} as any,
      {} as any,
      {} as any,
    );

    const result = await controller.getIdentityConfig();

    expect(result.radiusServerProfiles).toEqual([]);
    expect(result.ldapServerProfiles).toEqual([]);
    expect(result.authenticationProfiles).toEqual([]);
    expect(result.settings.portalAuthenticationProfileId).toBeNull();
  });
});
