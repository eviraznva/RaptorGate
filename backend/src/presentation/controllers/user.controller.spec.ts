import { jest } from '@jest/globals';
import { Test, TestingModule } from '@nestjs/testing';
import { User } from '../../domain/entities/user.entity.js';
import { Role as DomainRole } from '../../domain/entities/role.entity.js';
import { Role } from '../../domain/enums/role.enum.js';
import { CreateUserUseCase } from '../../application/use-cases/create-user.use-case.js';
import { DeleteUserUseCase } from '../../application/use-cases/delete-user.use-case.js';
import { EditUserUseCase } from '../../application/use-cases/edit-user.use-case.js';
import { GetAllUsersUseCase } from '../../application/use-cases/get-all-users.use-case.js';
import { UserController } from './user.controller.js';

describe('UserController', () => {
  let controller: UserController;

  const createUserUseCase = {
    execute: jest.fn<CreateUserUseCase['execute']>(),
  };

  const deleteUserUseCase = {
    execute: jest.fn<DeleteUserUseCase['execute']>(),
  };

  const editUserUseCase = {
    execute: jest.fn<EditUserUseCase['execute']>(),
  };

  const getAllUsersUseCase = {
    execute: jest.fn<GetAllUsersUseCase['execute']>(),
  };

  function createUserEntity(): User {
    return User.create(
      'user-1',
      'marek',
      'hash',
      null,
      null,
      null,
      false,
      false,
      new Date('2026-04-23T12:00:00.000Z'),
      new Date('2026-04-23T12:00:00.000Z'),
      [DomainRole.create('role-admin', Role.Admin)],
    );
  }

  beforeEach(async () => {
    createUserUseCase.execute.mockReset();
    deleteUserUseCase.execute.mockReset();
    editUserUseCase.execute.mockReset();
    getAllUsersUseCase.execute.mockReset();

    const module: TestingModule = await Test.createTestingModule({
      controllers: [UserController],
      providers: [
        {
          provide: CreateUserUseCase,
          useValue: createUserUseCase,
        },
        {
          provide: DeleteUserUseCase,
          useValue: deleteUserUseCase,
        },
        {
          provide: EditUserUseCase,
          useValue: editUserUseCase,
        },
        {
          provide: GetAllUsersUseCase,
          useValue: getAllUsersUseCase,
        },
      ],
    }).compile();

    controller = module.get(UserController);
  });

  it('passes actorUserId to createUser use-case', async () => {
    const user = createUserEntity();
    createUserUseCase.execute.mockResolvedValue({ user });

    await controller.createUser(
      {
        username: 'marek',
        password: 'secret',
        roles: [Role.Admin],
      },
      { user: { id: 'actor-1' } } as never,
    );

    expect(createUserUseCase.execute).toHaveBeenCalledWith({
      username: 'marek',
      password: 'secret',
      roles: [Role.Admin],
      actorUserId: 'actor-1',
    });
  });

  it('passes actorUserId to editUser use-case', async () => {
    const user = createUserEntity();
    editUserUseCase.execute.mockResolvedValue({ user });

    await controller.editUser(
      {
        username: 'marek-2',
      },
      'user-1',
      { user: { id: 'actor-2' } } as never,
    );

    expect(editUserUseCase.execute).toHaveBeenCalledWith({
      id: 'user-1',
      username: 'marek-2',
      actorUserId: 'actor-2',
    });
  });

  it('passes actorUserId to deleteUser use-case', async () => {
    deleteUserUseCase.execute.mockResolvedValue(undefined);

    await controller.deleteUser('user-1', { user: { id: 'actor-3' } } as never);

    expect(deleteUserUseCase.execute).toHaveBeenCalledWith({
      userId: 'user-1',
      actorUserId: 'actor-3',
    });
  });
});
