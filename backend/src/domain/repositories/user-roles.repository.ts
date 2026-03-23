import { UserRole } from '../entities/user-roles.entity';

export interface IUserRolesRepository {
  findAll(): Promise<UserRole[]>;
}

export const USER_ROLES_REPOSITORY_TOKEN = Symbol(
  'USER_ROLES_REPOSITORY_TOKEN',
);
