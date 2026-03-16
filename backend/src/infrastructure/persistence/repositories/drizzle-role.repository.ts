import { IRoleRepository } from 'src/domain/repositories/role.repository';
import {
  rolesTable,
  rolePermissionsTable,
  userRolesTable,
} from '../schemas/roles.schema';
import { permissionsTable } from '../schemas/permissions.schema';
import { PermissionMapper } from '../mappers/permission.mapper';
import { DB_CONNECTION } from '../database/database.module';
import { NodePgDatabase } from 'drizzle-orm/node-postgres';
import { Role } from 'src/domain/entities/role.entity';
import { RoleMapper } from '../mappers/role.mapper';
import { Inject, Injectable } from '@nestjs/common';
import { eq, inArray } from 'drizzle-orm';

@Injectable()
export class DrizzleRoleRepository implements IRoleRepository {
  constructor(@Inject(DB_CONNECTION) private readonly db: NodePgDatabase) {}
  private async loadPermissionsForRoles(
    roleIds: string[],
  ): Promise<Map<string, ReturnType<typeof PermissionMapper.toDomain>[]>> {
    if (roleIds.length === 0) return new Map();

    const rows = await this.db
      .select({
        roleId: rolePermissionsTable.roleId,
        permission: permissionsTable,
      })
      .from(rolePermissionsTable)
      .innerJoin(
        permissionsTable,
        eq(rolePermissionsTable.permissionId, permissionsTable.id),
      )
      .where(inArray(rolePermissionsTable.roleId, roleIds));

    const map = new Map<
      string,
      ReturnType<typeof PermissionMapper.toDomain>[]
    >();

    for (const row of rows) {
      if (!map.has(row.roleId)) map.set(row.roleId, []);
      map.get(row.roleId)!.push(PermissionMapper.toDomain(row.permission));
    }

    return map;
  }

  async findById(id: string): Promise<Role | null> {
    const [row] = await this.db
      .select()
      .from(rolesTable)
      .where(eq(rolesTable.id, id));

    if (!row) return null;

    const permMap = await this.loadPermissionsForRoles([id]);

    return RoleMapper.toDomain(row, permMap.get(id) ?? []);
  }

  async findByName(name: string): Promise<Role | null> {
    const [row] = await this.db
      .select()
      .from(rolesTable)
      .where(eq(rolesTable.name, name));

    if (!row) return null;

    const permMap = await this.loadPermissionsForRoles([row.id]);

    return RoleMapper.toDomain(row, permMap.get(row.id) ?? []);
  }

  async findByUserId(userId: string): Promise<Role[]> {
    const rows = await this.db
      .select({ role: rolesTable })
      .from(userRolesTable)
      .innerJoin(rolesTable, eq(userRolesTable.roleId, rolesTable.id))
      .where(eq(userRolesTable.userId, userId));

    if (rows.length === 0) return [];

    const roleIds = rows.map((r) => r.role.id);
    const permMap = await this.loadPermissionsForRoles(roleIds);

    return rows.map((r) =>
      RoleMapper.toDomain(r.role, permMap.get(r.role.id) ?? []),
    );
  }

  async findAll(): Promise<Role[]> {
    const rows = await this.db.select().from(rolesTable);

    if (rows.length === 0) return [];

    const roleIds = rows.map((r) => r.id);
    const permMap = await this.loadPermissionsForRoles(roleIds);

    return rows.map((r) => RoleMapper.toDomain(r, permMap.get(r.id) ?? []));
  }

  async save(role: {
    id: string;
    name: string;
    description?: string;
  }): Promise<void> {
    await this.db
      .insert(rolesTable)
      .values({
        id: role.id,
        name: role.name,
        description: role.description ?? null,
      })
      .onConflictDoNothing();
  }

  async assignToUser(userId: string, roleId: string): Promise<void> {
    await this.db
      .insert(userRolesTable)
      .values({ userId, roleId })
      .onConflictDoNothing();
  }

  async removeFromUser(userId: string, roleId: string): Promise<void> {
    await this.db
      .delete(userRolesTable)
      .where(
        eq(userRolesTable.userId, userId) && eq(userRolesTable.roleId, roleId),
      );
  }

  async setUserRoles(userId: string, roleIds: string[]): Promise<void> {
    await this.db
      .delete(userRolesTable)
      .where(eq(userRolesTable.userId, userId));

    if (roleIds.length === 0) return;

    await this.db
      .insert(userRolesTable)
      .values(roleIds.map((roleId) => ({ userId, roleId })));
  }

  async addPermissionToRole(
    roleId: string,
    permissionId: string,
  ): Promise<void> {
    await this.db
      .insert(rolePermissionsTable)
      .values({ roleId, permissionId })
      .onConflictDoNothing();
  }

  async setRolePermissions(
    roleId: string,
    permissionIds: string[],
  ): Promise<void> {
    await this.db
      .delete(rolePermissionsTable)
      .where(eq(rolePermissionsTable.roleId, roleId));

    if (permissionIds.length === 0) return;

    await this.db
      .insert(rolePermissionsTable)
      .values(permissionIds.map((permissionId) => ({ roleId, permissionId })));
  }
}
