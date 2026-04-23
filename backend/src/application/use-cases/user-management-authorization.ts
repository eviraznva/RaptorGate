import { ForbiddenException } from '@nestjs/common';
import { Role as RoleEntity } from '../../domain/entities/role.entity.js';
import { Role } from '../../domain/enums/role.enum.js';

function hasRole(roles: RoleEntity[], roleName: Role): boolean {
  return roles.some((role) => role.getName() === roleName);
}

export function ensureActorCanManageRoles(
  actorRoles: RoleEntity[],
  targetRoles: RoleEntity[],
): void {
  if (hasRole(actorRoles, Role.SuperAdmin)) {
    return;
  }

  if (hasRole(actorRoles, Role.Admin) && !hasRole(targetRoles, Role.SuperAdmin)) {
    return;
  }

  throw new ForbiddenException('Forbidden: insufficient permissions');
}
