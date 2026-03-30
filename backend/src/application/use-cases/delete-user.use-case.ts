import {
  type IRoleRepository,
  ROLE_REPOSITORY_TOKEN,
} from 'src/domain/repositories/role.repository';
import {
  type IUserRepository,
  USER_REPOSITORY_TOKEN,
} from 'src/domain/repositories/user.repository';
import { EntityNotFoundException } from 'src/domain/exceptions/entity-not-found-exception';
import { DleteUserDto } from '../dtos/delete-user.dto';
import { Inject, Injectable } from '@nestjs/common';

@Injectable()
export class DeleteUserUseCase {
  constructor(
    @Inject(USER_REPOSITORY_TOKEN)
    private readonly userRepository: IUserRepository,
    @Inject(ROLE_REPOSITORY_TOKEN)
    private readonly roleRepository: IRoleRepository,
  ) {}

  async execute(dto: DleteUserDto): Promise<void> {
    const user = await this.userRepository.findById(dto.userId);
    if (!user) throw new EntityNotFoundException('user', dto.userId);

    const userRoles = await this.roleRepository.findByUserId(dto.userId);

    await Promise.all(
      userRoles.map(
        async (role) =>
          await this.roleRepository.removeFromUser(user.getId(), role.getId()),
      ),
    );

    await this.userRepository.deleteById(user.getId());
  }
}
