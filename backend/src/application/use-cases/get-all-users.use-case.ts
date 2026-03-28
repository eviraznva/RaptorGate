import {
  USER_REPOSITORY_TOKEN,
  type IUserRepository,
} from 'src/domain/repositories/user.repository';
import {
  ROLE_REPOSITORY_TOKEN,
  type IRoleRepository,
} from 'src/domain/repositories/role.repository';
import { Inject, Injectable } from '@nestjs/common';
import { GetAllUsersResponseDto } from '../dtos/get-all-users-response.dto';
import { EntityNotFoundException } from 'src/domain/exceptions/entity-not-found-exception';

@Injectable()
export class GetAllUsersUseCase {
  constructor(
    @Inject(USER_REPOSITORY_TOKEN)
    private readonly userRepository: IUserRepository,
    @Inject(ROLE_REPOSITORY_TOKEN)
    private readonly roleRepository: IRoleRepository,
  ) {}

  async execute(): Promise<GetAllUsersResponseDto> {
    const users = await this.userRepository.findAll();
    if (!users) throw new EntityNotFoundException('User', 'all');

    const userWithRoles = await Promise.all(
      users.map(async (user) => {
        const role = await this.roleRepository.findByUserId(user.getId());
        user.setRoles(role);
        return user;
      }),
    );

    const mappedUsers = userWithRoles.map((user) => {
      return {
        id: user.getId(),
        username: user.getUsername(),
        createdAt: user.getCreatedAt(),
        updatedAt: user.getUpdatedAt(),
        roles: user.getRoles().map((role) => role.getName()),
      };
    });

    return {
      users: mappedUsers,
    };
  }
}
