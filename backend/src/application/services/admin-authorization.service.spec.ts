import { jest } from '@jest/globals';
import { IdentityAuthenticationProfile } from '../../domain/entities/identity-authentication-profile.entity.js';
import { Role as RoleEntity } from '../../domain/entities/role.entity.js';
import { Role } from '../../domain/enums/role.enum.js';
import type { IIdentityConfigRepository } from '../../domain/repositories/identity-config.repository.js';
import type { IRoleRepository } from '../../domain/repositories/role.repository.js';
import { AdminAuthorizationService } from './admin-authorization.service.js';

const now = new Date('2026-05-02T10:00:00.000Z');

describe('AdminAuthorizationService', () => {
  function authProfile(mappings = [
    { matchType: 'ldap_group' as const, matchValue: 'admins', role: Role.Admin },
  ]): IdentityAuthenticationProfile {
    return IdentityAuthenticationProfile.create(
      'auth-1',
      'Admin auth',
      null,
      true,
      'radius',
      'radius-1',
      'ldap-1',
      'ldap',
      1800,
      now,
      now,
      'creator',
      mappings,
    );
  }

  function service(profile = authProfile()): AdminAuthorizationService {
    const config = {
      getAuthenticationProfiles: () => [profile],
    };
    const identityConfigRepository = {
      find: jest.fn(async () => config),
    } as unknown as IIdentityConfigRepository;
    const roleRepository = {
      findByName: jest.fn(async (name: string) =>
        RoleEntity.create(`role-${name}`, name, null, []),
      ),
    } as unknown as IRoleRepository;

    return new AdminAuthorizationService(identityConfigRepository, roleRepository);
  }

  it('authorizes an admin by ldap group mapping', async () => {
    const result = await service().authorize({
      kind: 'accept',
      provider: 'radius',
      username: 'admin',
      groups: ['admins'],
      groupSource: 'ldap',
      externalId: 'uid=admin,dc=example,dc=com',
      sessionTtlSeconds: 1800,
      nasIp: '127.0.0.1',
      calledStationId: 'raptorgate',
      profileId: 'auth-1',
    });

    expect(result).toEqual({
      kind: 'authorized',
      role: Role.Admin,
      matchedBy: 'ldap_group',
      matchedValue: 'admins',
    });
  });

  it('denies accepted external credentials without a role mapping', async () => {
    const result = await service(authProfile([])).authorize({
      kind: 'accept',
      provider: 'radius',
      username: 'admin',
      groups: ['admins'],
      groupSource: 'ldap',
      externalId: 'uid=admin,dc=example,dc=com',
      sessionTtlSeconds: 1800,
      nasIp: '127.0.0.1',
      calledStationId: 'raptorgate',
      profileId: 'auth-1',
    });

    expect(result.kind).toBe('denied');
  });
});
