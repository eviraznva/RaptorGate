import { ForbiddenException } from '@nestjs/common';
import type { ExecutionContext } from '@nestjs/common';
import { Reflector } from '@nestjs/core';
import { Permission as PermissionEntity } from '../../domain/entities/permission.entity.js';
import { Role as RoleEntity } from '../../domain/entities/role.entity.js';
import { Permission } from '../../domain/enums/permissions.enum.js';
import { Role } from '../../domain/enums/role.enum.js';
import type { IAdminAuthSessionRepository } from '../../domain/repositories/admin-auth-session.repository.js';
import type { IRoleRepository } from '../../domain/repositories/role.repository.js';
import type { ITokenService } from '../../application/ports/token-service.interface.js';
import { REQUIRE_PERMISSIONS_KEY } from '../../presentation/decorators/auth/require-permissions.decorator.js';
import { ROLES_KEY } from '../../presentation/decorators/auth/roles.decorator.js';
import { RolesPermissionsGuard } from './roles-permissions.guard.js';

describe('RolesPermissionsGuard role hierarchy', () => {
  function context(): ExecutionContext {
    return {
      getHandler: jest.fn(),
      getClass: jest.fn(),
      switchToHttp: () => ({
        getRequest: () => ({
          headers: { authorization: 'Bearer access-token' },
        }),
      }),
    } as unknown as ExecutionContext;
  }

  function guard(input: {
    requiredRoles?: Role[];
    requiredPermissions?: Permission[];
    roles: RoleEntity[];
  }): RolesPermissionsGuard {
    const reflector = {
      getAllAndOverride: jest.fn((key: string) => {
        if (key === ROLES_KEY) return input.requiredRoles;
        if (key === REQUIRE_PERMISSIONS_KEY) return input.requiredPermissions;
        return undefined;
      }),
    } as unknown as Reflector;
    const tokenService = {
      verifyAccessToken: jest.fn(async () => ({
        sub: 'user-1',
        username: 'admin',
      })),
    } as unknown as jest.Mocked<ITokenService>;
    const roleRepository = {
      findByUserId: jest.fn(async () => input.roles),
    } as unknown as jest.Mocked<IRoleRepository>;
    const adminAuthSessionRepository = {
      findById: jest.fn(),
    } as unknown as jest.Mocked<IAdminAuthSessionRepository>;

    return new RolesPermissionsGuard(
      reflector,
      tokenService,
      roleRepository,
      adminAuthSessionRepository,
    );
  }

  it('allows super_admin through viewer role requirements', async () => {
    const role = RoleEntity.create('role-super-admin', Role.SuperAdmin, null, [
      PermissionEntity.create('perm-users-read', Permission.USERS_READ),
    ]);

    await expect(
      guard({
        requiredRoles: [Role.Viewer],
        roles: [role],
      }).canActivate(context()),
    ).resolves.toBe(true);
  });

  it('does not allow viewer through admin role requirements', async () => {
    const role = RoleEntity.create('role-viewer', Role.Viewer, null, []);

    await expect(
      guard({
        requiredRoles: [Role.Admin],
        roles: [role],
      }).canActivate(context()),
    ).rejects.toBeInstanceOf(ForbiddenException);
  });
});
