import { UserItemResponseDto } from './user-item-response.dto';
import { ApiProperty } from '@nestjs/swagger';

export class CreateUserResponseDto {
  @ApiProperty({
    type: () => UserItemResponseDto,
    example: {
      id: 'c1f6a5d2-8c3f-4c7f-9f1d-2d3e4f5a6b7c',
      username: 'JohnDoe',
      createdAt: '2026-03-28T10:15:30.000Z',
      updatedAt: '2026-03-28T10:15:30.000Z',
      roles: ['Admin', 'Viewer'],
    },
  })
  user: UserItemResponseDto;
}
