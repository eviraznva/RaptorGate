import { User } from '../entities/user.entity.js';

export interface IUserRepository {
  save(user: User): Promise<void>;
  findByUsername(username: string): Promise<User | null>;
  findById(id: string): Promise<User | null>;
  findAll(): Promise<User[]>;
  setRefreshToken(
    id: string,
    refreshToken: string | null,
    refreshTokenExpires: Date | null,
  ): Promise<void>;
  deleteById(id: string): Promise<void>;
}

export const USER_REPOSITORY_TOKEN = Symbol('USER_REPOSITORY_TOKEN');
