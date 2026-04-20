import { UserItemResponseDto } from '../dtos/user-item-response.dto';
import { User } from '../../domain/entities/user.entity.js';

export class UserResponseMapper {
  static toDto(user: User): UserItemResponseDto {
    return {
      id: user.getId(),
      username: user.getUsername(),
      createdAt: user.getCreatedAt().toISOString(),
      updatedAt: user.getUpdatedAt().toISOString(),
      roles: user.getRoles().map((role) => role.getName()),
      isFirstLogin: user.getIsFirstLogin(),
    };
  }
}
