import { ROLE_PERMISSIONS } from '../src/domain/constants/role-permissions';
import { Permission } from '../src/domain/enums/permissions.enum';
import { Role } from '../src/domain/enums/role.enum';
import { mkdir, writeFile } from 'node:fs/promises';
import { join } from 'node:path';
import * as bcrypt from 'bcrypt';

type JsonTable<T> = { items: T[] };

type UserRecord = {
  id: string;
  username: string;
  passwordHash: string;
  refreshToken: string | null;
  refreshTokenExpiry: string | null;
  createdAt: string;
  updatedAt: string;
};

type RoleRecord = {
  id: string;
  name: string;
  description: string | null;
};

type PermissionRecord = {
  id: string;
  name: string;
  description: string | null;
};

type UserRoleRecord = {
  userId: string;
  roleId: string;
};

type RolePermissionRecord = {
  roleId: string;
  permissionId: string;
};

const DB_DIR = join(process.cwd(), 'data', 'json-db');

const USER_ID = '00000000-0000-4000-8000-000000000001';

function seqUuid(sequence: number): string {
  return `00000000-0000-4000-8000-${sequence.toString(16).padStart(12, '0')}`;
}

function permissionDescription(permissionName: string): string {
  return `Permission ${permissionName}`;
}

async function writeJson<T>(fileName: string, payload: JsonTable<T> | object) {
  const filePath = join(DB_DIR, fileName);
  const text = JSON.stringify(payload, null, 2) + '\n';
  await writeFile(filePath, text, 'utf8');
}

async function main() {
  await mkdir(DB_DIR, { recursive: true });

  const now = new Date().toISOString();
  const saltRounds = Number.parseInt(
    process.env.BCRYPT_SALT_ROUNDS ?? '12',
    10,
  );
  const passwordHash = await bcrypt.hash('admin123', saltRounds);

  const rolesOrder: Role[] = [
    Role.SuperAdmin,
    Role.Admin,
    Role.Operator,
    Role.Viewer,
  ];

  const roles: RoleRecord[] = rolesOrder.map((name, idx) => ({
    id: seqUuid(100 + idx),
    name,
    description: `System role ${name}`,
  }));

  const roleIdByName = new Map(roles.map((r) => [r.name, r.id]));

  const permissionsValues = Object.values(Permission);
  const permissions: PermissionRecord[] = permissionsValues.map(
    (name, idx) => ({
      id: seqUuid(1000 + idx),
      name,
      description: permissionDescription(name),
    }),
  );

  const permissionIdByName = new Map(permissions.map((p) => [p.name, p.id]));

  const rolePermissions: RolePermissionRecord[] = [];
  for (const roleName of rolesOrder) {
    const roleId = roleIdByName.get(roleName);
    if (!roleId) continue;

    for (const permissionName of ROLE_PERMISSIONS[roleName]) {
      const permissionId = permissionIdByName.get(permissionName);
      if (!permissionId) continue;
      rolePermissions.push({ roleId, permissionId });
    }
  }

  const users: UserRecord[] = [
    {
      id: USER_ID,
      username: 'admin',
      passwordHash,
      refreshToken: null,
      refreshTokenExpiry: null,
      createdAt: now,
      updatedAt: now,
    },
  ];

  const userRoles: UserRoleRecord[] = [
    {
      userId: USER_ID,
      roleId: roleIdByName.get(Role.SuperAdmin)!,
    },
  ];

  await writeJson<UserRecord>('users.json', { items: users });
  await writeJson<RoleRecord>('roles.json', { items: roles });
  await writeJson<PermissionRecord>('permissions.json', { items: permissions });
  await writeJson<UserRoleRecord>('user_roles.json', { items: userRoles });
  await writeJson<RolePermissionRecord>('role_permissions.json', {
    items: rolePermissions,
  });

  const emptyTables = [
    'configuration_snapshots.json',
    'zones.json',
    'zone_pairs.json',
    'zone_interfaces.json',
    'rules.json',
    'rule_change_history.json',
    'nat_rules.json',
    'dns_blacklist.json',
    'ssl_bypass_list.json',
    'ips_signatures.json',
    'ml_models.json',
    'firewall_certificates.json',
    'identity_users.json',
    'identity_manager_user_sessions.json',
    'user_groups.json',
    'user_group_members.json',
    'sessions.json',
    'network_session_history.json',
  ];

  await Promise.all(
    emptyTables.map((tableName) => writeJson(tableName, { items: [] })),
  );

  await writeJson('_meta.json', {
    schemaVersion: 1,
    generatedAt: now,
    seed: {
      users: users.length,
      roles: roles.length,
      permissions: permissions.length,
      user_roles: userRoles.length,
      role_permissions: rolePermissions.length,
    },
    notes:
      'Seed generated from role.enum.ts, permissions.enum.ts and role-permissions.ts',
  });

  console.log('Seeded backend/data/json-db');
  console.log(`Admin username: admin`);
  console.log(`Admin password hash: ${passwordHash}`);
}

main().catch((error) => {
  console.error('Failed to seed backend/data/json-db', error);
  process.exit(1);
});
