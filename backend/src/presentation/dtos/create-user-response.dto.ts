import { ApiProperty } from '@nestjs/swagger';
import { Role } from 'src/domain/enums/role.enum';

export class CreateUserResponseDto {
  @ApiProperty({ example: 'c1f6a5d2-8c3f-4c7f-9f1d-2d3e4f5a6b7c' })
  id: string;

  @ApiProperty({ example: 'marek123' })
  username: string;

  @ApiProperty({
    example: '2026-03-28T10:15:30.000Z',
    type: String,
    format: 'date-time',
  })
  createdAt: Date;

  @ApiProperty({
    example: '2026-03-28T10:15:30.000Z',
    type: String,
    format: 'date-time',
  })
  updatedAt: Date;

  @ApiProperty({
    example: [Role.Admin, Role.Viewer],
    enum: Role,
    isArray: true,
    enumName: 'Role',
  })
  roles: string[];
}
