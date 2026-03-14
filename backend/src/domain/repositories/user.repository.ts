import { User } from '../entities/user.entity';
import { Role } from '../enums/role.enum';

export interface IUserRepository {
  save(user: User): Promise<void>;
  findByUsername(username: string): Promise<User | null>;
  findById(id: string): Promise<User | null>;
  findAll(): Promise<User[]>;
  updateRole(id: string, role: Role): Promise<void>;
  deleteById(id: string): Promise<void>;
}

export const USER_REPOSITORY_TOKEN = Symbol('USER_REPOSITORY_TOKEN');
