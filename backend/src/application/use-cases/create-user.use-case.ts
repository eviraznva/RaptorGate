import { Inject, Injectable, Logger } from "@nestjs/common";
import { User } from "src/domain/entities/user.entity";
import { RoleIsInvalidException } from "src/domain/exceptions/role-is-invalid.exception";
import { UserAlreadyExistsException } from "src/domain/exceptions/user-already-exitst.exception";
import {
  type IRoleRepository,
  ROLE_REPOSITORY_TOKEN,
} from "src/domain/repositories/role.repository";
import {
  type IUserRepository,
  USER_REPOSITORY_TOKEN,
} from "src/domain/repositories/user.repository";
import { CreateUserDto } from "../dtos/create-user.dto";
import { CreateUserResponseDto } from "../dtos/create-user-response.dto";
import {
  type IPasswordHasher,
  PASSWORD_HASHER_TOKEN,
} from "../ports/passowrd-hasher.interface";

@Injectable()
export class CreateUserUseCase {
  private readonly logger = new Logger(CreateUserUseCase.name);

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

    this.logger.log({
      event: "user.create.succeeded",
      message: "user created",
      userId: newUser.getId(),
      username: newUser.getUsername(),
      roles: userRoles.map((role) => role.getName()),
    });

    return {
      user: newUser,
    };
  }
}
