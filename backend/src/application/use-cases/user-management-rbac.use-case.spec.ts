import { jest } from '@jest/globals';
import { ForbiddenException } from '@nestjs/common';
import { User } from '../../domain/entities/user.entity.js';
import { Role as DomainRole } from '../../domain/entities/role.entity.js';
import { Role } from '../../domain/enums/role.enum.js';
import type { IRoleRepository } from '../../domain/repositories/role.repository.js';
import type { IUserRepository } from '../../domain/repositories/user.repository.js';
import type { IPasswordHasher } from '../ports/passowrd-hasher.interface.js';
import { CreateUserUseCase } from './create-user.use-case.js';
import { DeleteUserUseCase } from './delete-user.use-case.js';
import { EditUserUseCase } from './edit-user.use-case.js';

describe('User management RBAC', () => {
  const superAdminRole = DomainRole.create('role-super-admin', Role.SuperAdmin);
  const adminRole = DomainRole.create('role-admin', Role.Admin);
  const operatorRole = DomainRole.create('role-operator', Role.Operator);
  const viewerRole = DomainRole.create('role-viewer', Role.Viewer);

  const userRepository: jest.Mocked<IUserRepository> = {
    save: jest.fn(),
    findByUsername: jest.fn(),
    findById: jest.fn(),
    findAll: jest.fn(),
    setRefreshToken: jest.fn(),
    deleteById: jest.fn(),
  };

  const roleRepository: jest.Mocked<IRoleRepository> = {
    findById: jest.fn(),
    findByName: jest.fn(),
    findByUserId: jest.fn(),
    findAll: jest.fn(),
    save: jest.fn(),
    assignToUser: jest.fn(),
    removeFromUser: jest.fn(),
    setUserRoles: jest.fn(),
    addPermissionToRole: jest.fn(),
    setRolePermissions: jest.fn(),
  };

  const passwordHasher: jest.Mocked<IPasswordHasher> = {
    hash: jest.fn(),
    compare: jest.fn(),
  };

  function createUser(id: string, username: string): User {
    return User.create(
      id,
      username,
      'hash',
      null,
      null,
      null,
      false,
      false,
      new Date('2026-04-23T12:00:00.000Z'),
      new Date('2026-04-23T12:00:00.000Z'),
    );
  }

  beforeEach(() => {
    jest.clearAllMocks();
  });

  it('blocks an admin from creating a super admin', async () => {
    const useCase = new CreateUserUseCase(
      userRepository,
      passwordHasher,
      roleRepository,
    );

    userRepository.findByUsername.mockResolvedValue(null);
    roleRepository.findAll.mockResolvedValue([
      superAdminRole,
      adminRole,
      operatorRole,
      viewerRole,
    ]);
    roleRepository.findByUserId.mockResolvedValue([adminRole]);

    await expect(
      useCase.execute({
        username: 'new-user',
        password: 'secret',
        roles: [Role.SuperAdmin],
        actorUserId: 'actor-admin',
      }),
    ).rejects.toBeInstanceOf(ForbiddenException);

    expect(passwordHasher.hash).not.toHaveBeenCalled();
    expect(userRepository.save).not.toHaveBeenCalled();
  });

  it('replaces stored roles instead of appending them during edit', async () => {
    const useCase = new EditUserUseCase(
      userRepository,
      passwordHasher,
      roleRepository,
    );
    const targetUser = createUser('target-user', 'marek');

    userRepository.findById.mockResolvedValue(targetUser);
    roleRepository.findByUserId
      .mockResolvedValueOnce([superAdminRole])
      .mockResolvedValueOnce([adminRole, operatorRole])
      .mockResolvedValueOnce([viewerRole]);
    roleRepository.findAll.mockResolvedValue([
      superAdminRole,
      adminRole,
      operatorRole,
      viewerRole,
    ]);

    const result = await useCase.execute({
      id: 'target-user',
      roles: [Role.Viewer],
      actorUserId: 'actor-super-admin',
    });

    expect(roleRepository.setUserRoles).toHaveBeenCalledWith('target-user', [
      viewerRole.getId(),
    ]);
    expect(roleRepository.assignToUser).not.toHaveBeenCalled();
    expect(result.user.getRoles().map((role) => role.getName())).toEqual([
      Role.Viewer,
    ]);
  });

  it('blocks an admin from editing a super admin', async () => {
    const useCase = new EditUserUseCase(
      userRepository,
      passwordHasher,
      roleRepository,
    );
    const targetUser = createUser('target-super-admin', 'root');

    userRepository.findById.mockResolvedValue(targetUser);
    roleRepository.findByUserId
      .mockResolvedValueOnce([adminRole])
      .mockResolvedValueOnce([superAdminRole]);

    await expect(
      useCase.execute({
        id: 'target-super-admin',
        username: 'new-root',
        actorUserId: 'actor-admin',
      }),
    ).rejects.toBeInstanceOf(ForbiddenException);

    expect(userRepository.save).not.toHaveBeenCalled();
    expect(roleRepository.setUserRoles).not.toHaveBeenCalled();
  });

  it('blocks an admin from deleting a super admin', async () => {
    const useCase = new DeleteUserUseCase(userRepository, roleRepository);
    const targetUser = createUser('target-super-admin', 'root');

    userRepository.findById.mockResolvedValue(targetUser);
    roleRepository.findByUserId
      .mockResolvedValueOnce([adminRole])
      .mockResolvedValueOnce([superAdminRole]);

    await expect(
      useCase.execute({
        userId: 'target-super-admin',
        actorUserId: 'actor-admin',
      }),
    ).rejects.toBeInstanceOf(ForbiddenException);

    expect(roleRepository.removeFromUser).not.toHaveBeenCalled();
    expect(userRepository.deleteById).not.toHaveBeenCalled();
  });
});
