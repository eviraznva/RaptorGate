import { jest } from '@jest/globals';
import { IdentityAuthenticationProfile } from '../../domain/entities/identity-authentication-profile.entity.js';
import { IdentityConfiguration } from '../../domain/entities/identity-configuration.entity.js';
import { IdentitySettings } from '../../domain/entities/identity-settings.entity.js';
import { LdapServerProfile } from '../../domain/entities/ldap-server-profile.entity.js';
import { RadiusServerProfile } from '../../domain/entities/radius-server-profile.entity.js';
import { SecretReferenceMissingException } from '../../domain/exceptions/secret-reference-missing.exception.js';
import type { ISecretStoreRepository } from '../../domain/repositories/secret-store.repository.js';
import { IdentitySecretReferenceValidatorService } from './identity-secret-reference-validator.service.js';

describe('IdentitySecretReferenceValidatorService', () => {
  const now = new Date('2026-04-30T10:00:00.000Z');

  function config(radiusRef: string, ldapRef: string): IdentityConfiguration {
    const radius = RadiusServerProfile.create(
      'radius-1',
      'Radius',
      null,
      true,
      '127.0.0.1',
      1812,
      radiusRef,
      3000,
      1,
      null,
      null,
      null,
      now,
      now,
      'user-1',
    );
    const ldap = LdapServerProfile.create(
      'ldap-1',
      'LDAP',
      null,
      true,
      '127.0.0.1',
      389,
      'disabled',
      'cn=admin,dc=example,dc=com',
      ldapRef,
      'ou=users,dc=example,dc=com',
      'uid',
      'ou=groups,dc=example,dc=com',
      'memberUid',
      'cn',
      3000,
      300,
      now,
      now,
      'user-1',
    );
    const auth = IdentityAuthenticationProfile.create(
      'auth-1',
      'Auth',
      null,
      true,
      'radius',
      'radius-1',
      'ldap-1',
      'ldap',
      1800,
      now,
      now,
      'user-1',
    );

    return IdentityConfiguration.create(
      [radius],
      [ldap],
      [auth],
      IdentitySettings.create('auth-1', null, now, 'user-1'),
    );
  }

  it('accepts existing managed secret references', async () => {
    const service = new IdentitySecretReferenceValidatorService({
      exists: jest.fn(async () => true),
    } as unknown as ISecretStoreRepository);

    await expect(
      service.validateActiveConfig(
        config('secret://identity/radius/default', 'secret://identity/ldap/default'),
      ),
    ).resolves.toBeUndefined();
  });

  it('allows environment references for compatibility', async () => {
    const secretRepository = {
      exists: jest.fn(async () => false),
    } as unknown as jest.Mocked<ISecretStoreRepository>;
    const service = new IdentitySecretReferenceValidatorService(secretRepository);

    await expect(
      service.validateActiveConfig(
        config('env:RADIUS_SECRET', 'env:IDENTITY_LDAP_BIND_PASSWORD'),
      ),
    ).resolves.toBeUndefined();
    expect(secretRepository.exists).not.toHaveBeenCalled();
  });

  it('rejects missing managed secret references', async () => {
    const service = new IdentitySecretReferenceValidatorService({
      exists: jest.fn(async (ref: string) => ref !== 'secret://identity/ldap/default'),
    } as unknown as ISecretStoreRepository);

    await expect(
      service.validateActiveConfig(
        config('secret://identity/radius/default', 'secret://identity/ldap/default'),
      ),
    ).rejects.toThrow(SecretReferenceMissingException);
  });
});
