import { Inject, Injectable } from '@nestjs/common';
import { EntityNotFoundException } from '../../domain/exceptions/entity-not-found-exception.js';
import {
  type IRoleRepository,
  ROLE_REPOSITORY_TOKEN,
} from '../../domain/repositories/role.repository.js';
import {
  type IUserRepository,
  USER_REPOSITORY_TOKEN,
} from '../../domain/repositories/user.repository.js';
import { GetAllUsersResponseDto } from '../dtos/get-all-users-response.dto';
import { GetUsersDto } from '../dtos/get-users.dto';

@Injectable()
export class GetAllUsersUseCase {
  constructor(
    @Inject(USER_REPOSITORY_TOKEN)
    private readonly userRepository: IUserRepository,
    @Inject(ROLE_REPOSITORY_TOKEN)
    private readonly roleRepository: IRoleRepository,
  ) {}

  async execute(dto: GetUsersDto): Promise<GetAllUsersResponseDto> {
    const users = await this.userRepository.findAll();
    if (!users) throw new EntityNotFoundException('User', 'all');

    const userWithRoles = await Promise.all(
      users.map(async (user) => {
        const role = await this.roleRepository.findByUserId(user.getId());
        user.setRoles(role);
        return user;
      }),
    );

    let result = userWithRoles;

    if (dto.role !== undefined)
      result = result.filter((user) =>
        user.getRoles().some((r) => r.getName() === dto.role),
      );

    if (dto.page !== undefined && dto.limit !== undefined)
      result = result.slice((dto.page - 1) * dto.limit, dto.page * dto.limit);

    return {
      users: result,
    };
  }
}
