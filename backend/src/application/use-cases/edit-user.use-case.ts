import { Inject, Injectable, Logger } from "@nestjs/common";
import { AtLeastOneFieldRequiredException } from "../../domain/exceptions/at-least-one-field-required.exception.js";
import { EntityNotFoundException } from "../../domain/exceptions/entity-not-found-exception.js";
import { RoleIsInvalidException } from "../../domain/exceptions/role-is-invalid.exception.js";
import {
  type IRoleRepository,
  ROLE_REPOSITORY_TOKEN,
} from "../../domain/repositories/role.repository.js";
import {
  type IUserRepository,
  USER_REPOSITORY_TOKEN,
} from "../../domain/repositories/user.repository.js";
import { EditUserDto } from "../dtos/edit-user.dto";
import { EditUserResponseDto } from "../dtos/edit-user-response.dto";
import {
  type IPasswordHasher,
  PASSWORD_HASHER_TOKEN,
} from "../ports/passowrd-hasher.interface";

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
    if (!user) throw new EntityNotFoundException("User", dto.id);

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

    this.logger.log({
      event: "user.update.succeeded",
      message: "user updated",
      userId: user.getId(),
      username: user.getUsername(),
      roles: userRoles.map((role) => role.getName()),
      changedFields: Object.entries(dto)
        .filter(([key, value]) => key !== "id" && value !== undefined)
        .map(([key]) => key),
    });

    return { user };
  }
}
