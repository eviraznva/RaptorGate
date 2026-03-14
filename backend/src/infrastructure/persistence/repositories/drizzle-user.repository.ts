import { IUserRepository } from 'src/domain/repositories/user.repository';
import { DB_CONNECTION } from '../database/database.module';
import { NodePgDatabase } from 'drizzle-orm/node-postgres';
import { User } from 'src/domain/entities/user.entity';
import { usersTable } from '../schemas/users.schema';
import { UserMapper } from '../mappers/user.mapper';
import { Inject, Injectable } from '@nestjs/common';
import { Role } from 'src/domain/enums/role.enum';
import { eq } from 'drizzle-orm';

@Injectable()
export class DrizzleUserRepository implements IUserRepository {
  constructor(@Inject(DB_CONNECTION) private readonly db: NodePgDatabase) {}

  async save(user: User): Promise<void> {
    const newUser = UserMapper.toPersistence(user);

    await this.db.insert(usersTable).values({ ...newUser });
  }

  async findByUsername(username: string): Promise<User | null> {
    const [result] = await this.db
      .select()
      .from(usersTable)
      .where(eq(usersTable.username, username));

    if (!result) return null;

    return UserMapper.toDomain(result);
  }

  async findById(id: string): Promise<User | null> {
    const [result] = await this.db
      .select()
      .from(usersTable)
      .where(eq(usersTable.id, id));

    if (!result) return null;

    return UserMapper.toDomain(result);
  }

  async findAll(): Promise<User[]> {
    const result = await this.db.select().from(usersTable);

    const users: User[] = [];

    for (const user of result) {
      users.push(UserMapper.toDomain(user));
    }

    return users;
  }

  async updateRole(id: string, role: Role): Promise<void> {
    const user = await this.findById(id);

    if (!user) return;

    await this.db
      .update(usersTable)
      .set({ role: role })
      .where(eq(usersTable.id, user.getId()));
  }

  async deleteById(id: string): Promise<void> {
    const user = await this.findById(id);
    if (!user) return;

    await this.db.delete(usersTable).where(eq(usersTable.id, user?.getId()));
  }
}
