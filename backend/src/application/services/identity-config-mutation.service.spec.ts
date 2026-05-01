import { IdentityAuthenticationProfile } from '../../domain/entities/identity-authentication-profile.entity.js';
import { IdentityConfiguration } from '../../domain/entities/identity-configuration.entity.js';
import { IdentitySettings } from '../../domain/entities/identity-settings.entity.js';
import { LdapServerProfile } from '../../domain/entities/ldap-server-profile.entity.js';
import { RadiusServerProfile } from '../../domain/entities/radius-server-profile.entity.js';
import { IdentityProfileInUseException } from '../../domain/exceptions/identity-profile-in-use.exception.js';
import { IdentityProfileNotFoundException } from '../../domain/exceptions/identity-profile-not-found.exception.js';
import { IdentityConfigMutationService } from './identity-config-mutation.service.js';

describe('IdentityConfigMutationService', () => {
  const createdAt = new Date('2026-05-01T10:00:00.000Z');
  const updatedAt = new Date('2026-05-01T10:05:00.000Z');

  function radius(id = 'radius-1', name = 'Radius 1'): RadiusServerProfile {
    return RadiusServerProfile.create(
      id,
      name,
      null,
      true,
      '127.0.0.1',
      1812,
      'secret://identity/radius/default',
      3000,
      1,
      null,
      null,
      null,
      createdAt,
      createdAt,
      'creator',
    );
  }

  function ldap(id = 'ldap-1', name = 'LDAP 1'): LdapServerProfile {
    return LdapServerProfile.create(
      id,
      name,
      null,
      true,
      '127.0.0.1',
      389,
      'disabled',
      'cn=admin,dc=example,dc=com',
      'secret://identity/ldap/default',
      'ou=users,dc=example,dc=com',
      'uid',
      'ou=groups,dc=example,dc=com',
      'memberUid',
      'cn',
      3000,
      300,
      createdAt,
      createdAt,
      'creator',
    );
  }

  function auth(id = 'auth-1'): IdentityAuthenticationProfile {
    return IdentityAuthenticationProfile.create(
      id,
      'Portal Auth',
      null,
      true,
      'radius',
      'radius-1',
      'ldap-1',
      'ldap',
      1800,
      createdAt,
      createdAt,
      'creator',
    );
  }

  function config(): IdentityConfiguration {
    return IdentityConfiguration.create(
      [radius()],
      [ldap()],
      [auth()],
      IdentitySettings.create('auth-1', 'auth-1', createdAt, 'creator'),
    );
  }

  it('rejects deleting a radius profile used by an authentication profile', () => {
    const service = new IdentityConfigMutationService();

    expect(() => service.deleteRadiusProfile(config(), 'radius-1')).toThrow(
      IdentityProfileInUseException,
    );
  });

  it('rejects deleting an authentication profile used by settings', () => {
    const service = new IdentityConfigMutationService();

    expect(() => service.deleteAuthenticationProfile(config(), 'auth-1')).toThrow(
      IdentityProfileInUseException,
    );
  });

  it('throws not found when updating a missing ldap profile', () => {
    const service = new IdentityConfigMutationService();

    expect(() => service.replaceLdapProfile(config(), ldap('missing'))).toThrow(
      IdentityProfileNotFoundException,
    );
  });

  it('replaces a radius profile while preserving other profile groups', () => {
    const service = new IdentityConfigMutationService();
    const nextRadius = RadiusServerProfile.create(
      'radius-1',
      'Radius updated',
      'Updated',
      false,
      '10.0.0.10',
      1812,
      'secret://identity/radius/default',
      5000,
      2,
      null,
      null,
      null,
      createdAt,
      updatedAt,
      'creator',
    );

    const result = service.replaceRadiusProfile(config(), nextRadius);

    expect(result.getRadiusServerProfiles()[0].getName()).toBe('Radius updated');
    expect(result.getLdapServerProfiles()).toHaveLength(1);
    expect(result.getAuthenticationProfiles()).toHaveLength(1);
  });
});
