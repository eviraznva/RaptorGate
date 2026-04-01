import {
  ROLE_REPOSITORY_TOKEN,
  type IRoleRepository,
} from 'src/domain/repositories/role.repository';
import {
  USER_REPOSITORY_TOKEN,
  type IUserRepository,
} from 'src/domain/repositories/user.repository';
import {
  PASSWORD_HASHER_TOKEN,
  type IPasswordHasher,
} from '../ports/passowrd-hasher.interface';
import { AtLeastOneFieldRequiredException } from 'src/domain/exceptions/at-least-one-field-required.exception';
import { EntityNotFoundException } from 'src/domain/exceptions/entity-not-found-exception';
import { RoleIsInvalidException } from 'src/domain/exceptions/role-is-invalid.exception';
import { EditUserResponseDto } from '../dtos/edit-user-response.dto';
import { EditUserDto } from '../dtos/edit-user.dto';
import { Inject, Injectable } from '@nestjs/common';

@Injectable()
export class EditUserUseCase {
  constructor(
    @Inject(USER_REPOSITORY_TOKEN)
    private readonly userRepository: IUserRepository,
    @Inject(PASSWORD_HASHER_TOKEN)
    private readonly passwordHasher: IPasswordHasher,
    @Inject(ROLE_REPOSITORY_TOKEN)
    private readonly roleRepository: IRoleRepository,
  ) {}

  async execute(dto: EditUserDto): Promise<EditUserResponseDto> {
    const user = await this.userRepository.findById(dto.id);
    if (!user) throw new EntityNotFoundException('User', dto.id);

    const isAllUndefined = Object.values(dto).every(
      (value) => value == undefined,
    );
    if (isAllUndefined) throw new AtLeastOneFieldRequiredException();

    if (dto.username !== undefined) user.setUsername(dto.username);
    if (dto.password !== undefined) {
      const passwordHash = await this.passwordHasher.hash(dto.password);
      user.setPasswordHash(passwordHash);
    }
    if (dto.roles !== undefined) {
      const roles = await this.roleRepository.findAll();

      const isValidRole = dto.roles.every((role) => {
        const userRoleNames = roles.map((r) => r.getName());
        return userRoleNames.includes(role);
      });
      if (!isValidRole) throw new RoleIsInvalidException();

      const rolesToAssign = roles.filter((r) =>
        dto.roles!.includes(r.getName()),
      );

      user.setRoles(rolesToAssign);
    }

    user.setUpdatedAt(new Date());

    await this.userRepository.save(user);

    await Promise.all(
      user
        .getRoles()
        .map(
          async (role) =>
            await this.roleRepository.assignToUser(user.getId(), role.getId()),
        ),
    );

    const userRoles = await this.roleRepository.findByUserId(user.getId());
    user.setRoles(userRoles);

    return { user };
  }
}
