import {
  USER_REPOSITORY_TOKEN,
  type IUserRepository,
} from '../../domain/repositories/user.repository.js';
import {
  ROLE_REPOSITORY_TOKEN,
  type IRoleRepository,
} from '../../domain/repositories/role.repository.js';
import { Inject, Injectable } from '@nestjs/common';
import { GetAllUsersResponseDto } from '../dtos/get-all-users-response.dto';
import { EntityNotFoundException } from '../../domain/exceptions/entity-not-found-exception.js';

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

    return {
      users: userWithRoles,
    };
  }
}
