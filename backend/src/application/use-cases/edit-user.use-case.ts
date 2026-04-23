import {
  ROLE_REPOSITORY_TOKEN,
  type IRoleRepository,
} from '../../domain/repositories/role.repository.js';
import {
  USER_REPOSITORY_TOKEN,
  type IUserRepository,
} from '../../domain/repositories/user.repository.js';
import {
  PASSWORD_HASHER_TOKEN,
  type IPasswordHasher,
} from '../ports/passowrd-hasher.interface';
import { AtLeastOneFieldRequiredException } from '../../domain/exceptions/at-least-one-field-required.exception.js';
import { EntityNotFoundException } from '../../domain/exceptions/entity-not-found-exception.js';
import { RoleIsInvalidException } from '../../domain/exceptions/role-is-invalid.exception.js';
import { EditUserResponseDto } from '../dtos/edit-user-response.dto';
import { EditUserDto } from '../dtos/edit-user.dto';
import { ensureActorCanManageRoles } from './user-management-authorization.js';
import { Inject, Injectable, Logger } from '@nestjs/common';

@Injectable()
export class EditUserUseCase {
  private readonly logger = new Logger(EditUserUseCase.name);

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
    const actorRoles = await this.roleRepository.findByUserId(dto.actorUserId);
    const currentUserRoles = await this.roleRepository.findByUserId(user.getId());

    ensureActorCanManageRoles(actorRoles, currentUserRoles);

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

      ensureActorCanManageRoles(actorRoles, rolesToAssign);
      user.setRoles(rolesToAssign);
    }

    user.setUpdatedAt(new Date());

    await this.userRepository.save(user);

    if (dto.roles !== undefined) {
      await this.roleRepository.setUserRoles(
        user.getId(),
        user.getRoles().map((role) => role.getId()),
      );
    }

    const userRoles = await this.roleRepository.findByUserId(user.getId());
    user.setRoles(userRoles);

    this.logger.log({
      event: 'user.update.succeeded',
      message: 'user updated',
      userId: user.getId(),
      username: user.getUsername(),
      roles: userRoles.map((role) => role.getName()),
      changedFields: Object.entries(dto)
        .filter(
          ([key, value]) =>
            key !== 'id' && key !== 'actorUserId' && value !== undefined,
        )
        .map(([key]) => key),
    });

    return { user };
  }
}
