import { drizzle } from 'drizzle-orm/node-postgres';
import { Pool } from 'pg';
import { usersTable } from './src/infrastructure/persistence/schemas/users.schema';
import { Role } from './src/domain/enums/role.enum';
import * as bcrypt from 'bcrypt';
import * as dotenv from 'dotenv';
import { randomUUID } from 'crypto';
import { eq } from 'drizzle-orm';

dotenv.config();

async function seed() {
  const databaseUrl = process.env.DATABASE_URL;

  if (!databaseUrl) {
    console.error('❌ DATABASE_URL is not defined in environment variables');
    process.exit(1);
  }

  const pool = new Pool({
    connectionString: databaseUrl,
  });

  const db = drizzle({ client: pool });

  try {
    // Check if super_admin already exists
    const existingUsers = await db
      .select()
      .from(usersTable)
      .where(eq(usersTable.username, 'admin'));

    if (existingUsers.length > 0) {
      console.log('⚠️  User "admin" already exists. Skipping...');
      await pool.end();
      return;
    }

    // Hash password
    const saltRounds = parseInt(process.env.BCRYPT_SALT_ROUNDS || '12', 10);
    const passwordHash = await bcrypt.hash('admin123', saltRounds);

    // Insert super_admin user
    await db.insert(usersTable).values({
      id: randomUUID(),
      username: 'admin',
      passwordHash,
      role: Role.SuperAdmin,
      createdAt: new Date(),
      updatedAt: new Date(),
    });

    console.log('✅ Super admin user created successfully!');
    console.log('   Username: admin');
    console.log('   Password: admin123');
    console.log('   Role: super_admin');
  } catch (error) {
    console.error('❌ Error seeding database:', error);
    process.exit(1);
  } finally {
    await pool.end();
  }
}

seed();
