import { configurationSnapshotsTable } from './src/infrastructure/persistence/schemas/configuration-snapshots.schema';
import { usersTable } from './src/infrastructure/persistence/schemas/users.schema';
import { drizzle } from 'drizzle-orm/node-postgres';
import { Role } from './src/domain/enums/role.enum';
import { randomUUID } from 'crypto';
import * as bcrypt from 'bcrypt';
import * as dotenv from 'dotenv';
import { eq } from 'drizzle-orm';
import { Pool } from 'pg';
import { ROLE_PERMISSIONS } from 'src/domain/constants/role-permissions';
import { Permission } from 'src/domain/enums/permissions.enum';
import { permissionsTable } from 'src/infrastructure/persistence/schemas/permissions.schema';
import {
  rolesTable,
  rolePermissionsTable,
  userRolesTable,
} from 'src/infrastructure/persistence/schemas/roles.schema';
dotenv.config();
const PAYLOAD = {
  section_versions: {
    rules: 15,
    zones: 3,
    zone_interfaces: 4,
    zone_pairs: 2,
    nat_rules: 7,
    dns_blacklist: 12,
    ssl_bypass_list: 5,
    ips_signatures: 23,
    ml_model: 2,
    certificates: 1,
    identity: 8,
  },
  bundle: {
    rules: {
      checksum:
        'b1c2d3e4f5a6b7c8d9e0f1a2b3c4d5e6f7a8b9c0d1e2f3a4b5c6d7e8f9a0b1c2',
      items: [
        {
          id: '018f4a11-0001-7000-a000-000000000001',
          name: 'allow-internal-to-dmz-http',
          zone_pair_id: '018f4a11-zp01-7000-a000-000000000001',
          priority: 10,
          content:
            'rule allow-internal-to-dmz-http {\n  match {\n    protocol tcp\n    dst_port 80 443\n  }\n  action ALLOW\n}',
        },
        {
          id: '018f4a11-0002-7000-a000-000000000002',
          name: 'block-ssh-from-untrusted',
          zone_pair_id: '018f4a11-zp02-7000-a000-000000000002',
          priority: 20,
          content:
            'rule block-ssh-from-untrusted {\n  match {\n    protocol tcp\n    dst_port 22\n  }\n  action DROP WARN\n}',
        },
        {
          id: '018f4a11-0003-7000-a000-000000000003',
          name: 'allow-dns-queries',
          zone_pair_id: '018f4a11-zp01-7000-a000-000000000001',
          priority: 30,
          content:
            'rule allow-dns-queries {\n  match {\n    protocol udp\n    dst_port 53\n  }\n  action ALLOW\n}',
        },
      ],
    },
    zones: {
      items: [
        { id: '018f4a11-z001-7000-a000-000000000001', name: 'internal' },
        { id: '018f4a11-z002-7000-a000-000000000002', name: 'dmz' },
        { id: '018f4a11-z003-7000-a000-000000000003', name: 'untrusted' },
      ],
    },
    zone_interfaces: {
      items: [
        {
          id: '018f4a11-zi01-7000-a000-000000000001',
          zone_id: '018f4a11-z001-7000-a000-000000000001',
          interface_name: 'eth0',
          vlan_id: null,
        },
        {
          id: '018f4a11-zi02-7000-a000-000000000002',
          zone_id: '018f4a11-z002-7000-a000-000000000002',
          interface_name: 'eth1',
          vlan_id: null,
        },
        {
          id: '018f4a11-zi03-7000-a000-000000000003',
          zone_id: '018f4a11-z001-7000-a000-000000000001',
          interface_name: 'eth0',
          vlan_id: 100,
        },
        {
          id: '018f4a11-zi04-7000-a000-000000000004',
          zone_id: '018f4a11-z003-7000-a000-000000000003',
          interface_name: 'eth2',
          vlan_id: null,
        },
      ],
    },
    zone_pairs: {
      items: [
        {
          id: '018f4a11-zp01-7000-a000-000000000001',
          src_zone_id: '018f4a11-z001-7000-a000-000000000001',
          dst_zone_id: '018f4a11-z002-7000-a000-000000000002',
          default_policy: 'DROP',
        },
        {
          id: '018f4a11-zp02-7000-a000-000000000002',
          src_zone_id: '018f4a11-z003-7000-a000-000000000003',
          dst_zone_id: '018f4a11-z001-7000-a000-000000000001',
          default_policy: 'DROP',
        },
      ],
    },
    nat_rules: {
      items: [
        {
          id: '018f4a11-nat1-7000-a000-000000000001',
          type: 'SNAT',
          src_ip: '10.0.0.0/24',
          dst_ip: '0.0.0.0/0',
          src_port: null,
          dst_port: null,
          translated_ip: '203.0.113.1',
          translated_port: null,
          priority: 10,
        },
        {
          id: '018f4a11-nat2-7000-a000-000000000002',
          type: 'DNAT',
          src_ip: '0.0.0.0/0',
          dst_ip: '203.0.113.1',
          src_port: null,
          dst_port: 8443,
          translated_ip: '10.0.1.10',
          translated_port: 443,
          priority: 20,
        },
      ],
    },
    dns_blacklist: {
      items: [
        {
          id: '018f4a11-dns1-7000-a000-000000000001',
          domain: 'malware-c2.example.com',
        },
        {
          id: '018f4a11-dns2-7000-a000-000000000002',
          domain: 'phishing.bad-domain.net',
        },
        {
          id: '018f4a11-dns3-7000-a000-000000000003',
          domain: 'crypto-miner.evil.org',
        },
      ],
    },
    ssl_bypass_list: {
      items: [
        {
          id: '018f4a11-ssl1-7000-a000-000000000001',
          domain: 'internal.corp.local',
        },
        {
          id: '018f4a11-ssl2-7000-a000-000000000002',
          domain: 'banking.trusted.pl',
        },
      ],
    },
    ips_signatures: {
      items: [
        {
          id: '018f4a11-ips1-7000-a000-000000000001',
          name: 'SQL Injection — UNION SELECT',
          category: 'sql_injection',
          pattern: '(?i)UNION\\s+SELECT',
          severity: 'HIGH',
        },
        {
          id: '018f4a11-ips2-7000-a000-000000000002',
          name: 'XSS — script tag',
          category: 'xss',
          pattern: '<script[^>]*>',
          severity: 'MEDIUM',
        },
        {
          id: '018f4a11-ips3-7000-a000-000000000003',
          name: 'Mirai botnet signature',
          category: 'botnet',
          pattern: '/bin/busybox\\s+MIRAI',
          severity: 'CRITICAL',
        },
        {
          id: '018f4a11-ips4-7000-a000-000000000004',
          name: 'Path traversal',
          category: 'path_traversal',
          pattern: '\\.\\./\\.\\./',
          severity: 'HIGH',
        },
      ],
    },
    ml_model: {
      id: '018f4a11-ml01-7000-a000-000000000001',
      name: 'raptorgate-anomaly-v2',
      artifact_path: '/var/lib/raptorgate/models/anomaly-v2.onnx',
      checksum:
        'f9e8d7c6b5a4f3e2d1c0b9a8f7e6d5c4b3a2f1e0d9c8b7a6f5e4d3c2b1a0f9e8',
    },
    firewall_certificates: {
      items: [
        {
          id: '018f4a11-cert-7000-a000-000000000001',
          cert_type: 'CA',
          common_name: 'RaptorGate Internal CA',
          fingerprint:
            'AA:BB:CC:DD:EE:FF:00:11:22:33:44:55:66:77:88:99:AA:BB:CC:DD',
          certificate_pem:
            '-----BEGIN CERTIFICATE-----\nMIIC...skrócone...==\n-----END CERTIFICATE-----',
          private_key_ref: 'vault:secret/raptorgate/ca-key',
          expires_at: '2028-03-14T00:00:00Z',
        },
      ],
    },
    identity: {
      user_groups: [
        {
          id: '018f4a11-ug01-7000-a000-000000000001',
          name: 'developers',
          source: 'LOCAL',
        },
        {
          id: '018f4a11-ug02-7000-a000-000000000002',
          name: 'admins',
          source: 'RADIUS',
        },
      ],
      identity_users: [
        {
          id: '018f4a11-iu01-7000-a000-000000000001',
          username: 'jan.kowalski',
          display_name: 'Jan Kowalski',
          source: 'LOCAL',
          external_id: '',
        },
      ],
      user_group_members: [
        {
          id: '018f4a11-ugm1-7000-a000-000000000001',
          group_id: '018f4a11-ug01-7000-a000-000000000001',
          identity_user_id: '018f4a11-iu01-7000-a000-000000000001',
        },
      ],
      user_sessions: [
        {
          id: '018f4a11-us01-7000-a000-000000000001',
          identity_user_id: '018f4a11-iu01-7000-a000-000000000001',
          radius_username: '',
          mac_address: 'AA:BB:CC:11:22:33',
          ip_address: '10.0.0.42',
          nas_ip: '10.0.0.1',
          called_station_id: '',
          authenticated_at: '2026-03-14T09:00:00Z',
          expires_at: '2026-03-14T17:00:00Z',
        },
      ],
    },
  },
};
async function seed() {
  const databaseUrl = process.env.DATABASE_URL;
  if (!databaseUrl) {
    console.error('❌ DATABASE_URL is not defined in environment variables');
    process.exit(1);
  }
  const pool = new Pool({ connectionString: databaseUrl });
  const db = drizzle({ client: pool });
  try {
    // ── User ──────────────────────────────────────────────────────────────────
    let admin = (
      await db.select().from(usersTable).where(eq(usersTable.username, 'admin'))
    )[0];
    if (admin) {
      console.log('⚠️  User "admin" already exists. Skipping...');
    } else {
      const saltRounds = parseInt(process.env.BCRYPT_SALT_ROUNDS || '12', 10);
      const passwordHash = await bcrypt.hash('admin123', saltRounds);
      await db.insert(usersTable).values({
        id: randomUUID(),
        username: 'admin',
        passwordHash,
        createdAt: new Date(),
        updatedAt: new Date(),
      });
      admin = (
        await db
          .select()
          .from(usersTable)
          .where(eq(usersTable.username, 'admin'))
      )[0];
      console.log('✅ Super admin user created successfully!');
      console.log('   Username: admin');
      console.log('   Password: admin123');
      console.log('   Role: super_admin');
      // ── Permissions ───────────────────────────────────────────────────────────
      const allPermissionNames = Object.values(Permission);
      const existingPerms = await db.select().from(permissionsTable);
      if (existingPerms.length === 0) {
        await db
          .insert(permissionsTable)
          .values(
            allPermissionNames.map((name) => ({ id: randomUUID(), name })),
          );
        console.log(`✅ Seeded ${allPermissionNames.length} permissions`);
      } else {
        console.log('⚠️  Permissions already seeded. Skipping...');
      }
      // ── Roles ─────────────────────────────────────────────────────────────────
      const allRoleNames = Object.values(Role); // ['super_admin', 'admin', 'operator', 'viewer']
      const existingRoles = await db.select().from(rolesTable);
      if (existingRoles.length === 0) {
        await db
          .insert(rolesTable)
          .values(allRoleNames.map((name) => ({ id: randomUUID(), name })));
        console.log(`✅ Seeded ${allRoleNames.length} roles`);
      } else {
        console.log('⚠️  Roles already seeded. Skipping...');
      }
      // ── Role → Permissions ────────────────────────────────────────────────────
      const permRows = await db.select().from(permissionsTable);
      const roleRows = await db.select().from(rolesTable);
      const permMap = new Map(permRows.map((p) => [p.name, p.id]));
      const roleMap = new Map(roleRows.map((r) => [r.name, r.id]));
      const existingRolePerms = await db.select().from(rolePermissionsTable);
      if (existingRolePerms.length === 0) {
        const toInsert: { roleId: string; permissionId: string }[] = [];
        for (const [roleName, permissions] of Object.entries(
          ROLE_PERMISSIONS,
        )) {
          const roleId = roleMap.get(roleName);
          if (!roleId) continue;
          for (const permName of permissions) {
            const permissionId = permMap.get(permName);
            if (permissionId) toInsert.push({ roleId, permissionId });
          }
        }
        if (toInsert.length > 0) {
          await db.insert(rolePermissionsTable).values(toInsert);
          console.log(
            `✅ Seeded ${toInsert.length} role-permission assignments`,
          );
        }
      } else {
        console.log('⚠️  Role permissions already seeded. Skipping...');
      }
      // ── Admin user roles ──────────────────────────────────────────────────────
      const existingUserRoles = await db
        .select()
        .from(userRolesTable)
        .where(eq(userRolesTable.userId, admin.id));
      if (existingUserRoles.length === 0) {
        const superAdminRoleId = roleMap.get(Role.SuperAdmin);
        if (superAdminRoleId) {
          await db.insert(userRolesTable).values({
            userId: admin.id,
            roleId: superAdminRoleId,
          });
          console.log('✅ Assigned super_admin role to admin user');
        }
      } else {
        console.log('⚠️  Admin user roles already assigned. Skipping...');
      }
    }
    // ── Snapshot ──────────────────────────────────────────────────────────────
    const existingSnapshot = await db
      .select()
      .from(configurationSnapshotsTable)
      .where(eq(configurationSnapshotsTable.isActive, true))
      .limit(1);
    if (existingSnapshot.length > 0) {
      console.log('⚠️  Active snapshot already exists. Skipping...');
    } else {
      await db.insert(configurationSnapshotsTable).values({
        id: randomUUID(),
        versionNumber: 1,
        snapshotType: 'manual_import', // ← poprawione z 'FULL'
        checksum:
          'b1c2d3e4f5a6b7c8d9e0f1a2b3c4d5e6f7a8b9c0d1e2f3a4b5c6d7e8f9a0b1c2',
        isActive: true,
        payloadJson: PAYLOAD,
        changeSummary: 'Initial seed',
        createdBy: admin.id,
      });
      console.log('✅ Configuration snapshot seeded successfully!');
    }
  } catch (error) {
    console.error('❌ Error seeding database:', error);
    process.exit(1);
  } finally {
    await pool.end();
  }
}

seed();
