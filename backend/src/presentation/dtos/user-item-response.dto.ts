import { Role } from 'src/domain/enums/role.enum';
import { ApiProperty } from '@nestjs/swagger';

export class UserItemResponseDto {
  @ApiProperty({ example: 'c1f6a5d2-8c3f-4c7f-9f1d-2d3e4f5a6b7c' })
  id: string;

  @ApiProperty({ example: 'marek123' })
  username: string;

  @ApiProperty({
    example: '2026-03-28T10:15:30.000Z',
    type: String,
    format: 'date-time',
  })
  createdAt: string;

  @ApiProperty({
    example: '2026-03-28T10:15:30.000Z',
    type: String,
    format: 'date-time',
  })
  updatedAt: string;

  @ApiProperty({
    example: [Role.Admin, Role.Viewer],
    enum: Role,
    isArray: true,
    enumName: 'Role',
  })
  roles: string[];
}
