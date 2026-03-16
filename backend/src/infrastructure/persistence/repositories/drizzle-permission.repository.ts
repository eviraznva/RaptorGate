import { IPermissionRepository } from 'src/domain/repositories/permission.repository';
import { Permission } from 'src/domain/entities/permission.entity';
import { permissionsTable } from '../schemas/permissions.schema';
import { PermissionMapper } from '../mappers/permission.mapper';
import { rolePermissionsTable } from '../schemas/roles.schema';
import { DB_CONNECTION } from '../database/database.module';
import { NodePgDatabase } from 'drizzle-orm/node-postgres';
import { Inject, Injectable } from '@nestjs/common';
import { eq } from 'drizzle-orm';

@Injectable()
export class DrizzlePermissionRepository implements IPermissionRepository {
  constructor(@Inject(DB_CONNECTION) private readonly db: NodePgDatabase) {}

  async findAll(): Promise<Permission[]> {
    const rows = await this.db.select().from(permissionsTable);

    return rows.map((row) => PermissionMapper.toDomain(row));
  }

  async findByName(name: string): Promise<Permission | null> {
    const [row] = await this.db
      .select()
      .from(permissionsTable)
      .where(eq(permissionsTable.name, name));

    return row ? PermissionMapper.toDomain(row) : null;
  }

  async findByRoleId(roleId: string): Promise<Permission[]> {
    const rows = await this.db
      .select({ permission: permissionsTable })
      .from(rolePermissionsTable)
      .innerJoin(
        permissionsTable,
        eq(rolePermissionsTable.permissionId, permissionsTable.id),
      )
      .where(eq(rolePermissionsTable.roleId, roleId));

    return rows.map((r) => PermissionMapper.toDomain(r.permission));
  }

  async saveAll(
    permissions: { id: string; name: string; description?: string }[],
  ): Promise<void> {
    if (permissions.length === 0) return;

    await this.db
      .insert(permissionsTable)
      .values(
        permissions.map((p) => ({
          id: p.id,
          name: p.name,
          description: p.description ?? null,
        })),
      )
      .onConflictDoNothing();
  }
}
