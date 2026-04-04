import {
  type IUserRepository,
  USER_REPOSITORY_TOKEN,
} from '../../domain/repositories/user.repository.js';
import {
  type IRoleRepository,
  ROLE_REPOSITORY_TOKEN,
} from '../../domain/repositories/role.repository.js';
import {
  type IPasswordHasher,
  PASSWORD_HASHER_TOKEN,
} from '../ports/passowrd-hasher.interface';
import { UserAlreadyExistsException } from '../../domain/exceptions/user-already-exitst.exception.js';
import { RoleIsInvalidException } from '../../domain/exceptions/role-is-invalid.exception.js';
import { CreateUserResponseDto } from '../dtos/create-user-response.dto';
import { CreateUserDto } from '../dtos/create-user.dto';
import { User } from '../../domain/entities/user.entity.js';
import { Inject, Injectable } from '@nestjs/common';

@Injectable()
export class CreateUserUseCase {
  constructor(
    @Inject(USER_REPOSITORY_TOKEN)
    private readonly userRepository: IUserRepository,
    @Inject(PASSWORD_HASHER_TOKEN)
    private readonly passwordHasher: IPasswordHasher,
    @Inject(ROLE_REPOSITORY_TOKEN)
    private readonly roleRepository: IRoleRepository,
  ) {}

  async execute(dto: CreateUserDto): Promise<CreateUserResponseDto> {
    const existingUser = await this.userRepository.findByUsername(dto.username);
    if (existingUser) throw new UserAlreadyExistsException();

    const roles = await this.roleRepository.findAll();
    const isValidRole = dto.roles.every((role) => {
      const userRoleNames = roles.map((r) => r.getName());
      return userRoleNames.includes(role);
    });
    if (!isValidRole) throw new RoleIsInvalidException();

    const rolesToAssign = roles.filter((r) => dto.roles.includes(r.getName()));

    const passwordHash = await this.passwordHasher.hash(dto.password);

    const newUser = User.create(
      crypto.randomUUID(),
      dto.username,
      passwordHash,
      null,
      null,
      null,
      true,
      true,
      new Date(),
      new Date(),
    );

    await this.userRepository.save(newUser);

    await Promise.all(
      rolesToAssign.map(
        async (role) =>
          await this.roleRepository.assignToUser(newUser.getId(), role.getId()),
      ),
    );

    const userRoles = await this.roleRepository.findByUserId(newUser.getId());
    newUser.setRoles(userRoles);

    return {
      user: newUser,
    };
  }
}
