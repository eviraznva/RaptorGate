import {
  IsString,
  MinLength,
  MaxLength,
  Matches,
  IsOptional,
} from 'class-validator';
import { Role } from '../../domain/enums/role.enum.js';
import { ApiProperty } from '@nestjs/swagger';

export class EditUserDto {
  @ApiProperty({ example: 'jankowal' })
  @IsString()
  @MinLength(3)
  @MaxLength(20)
  @Matches(/^[a-zA-Z][a-zA-Z0-9_-]*$/, {
    message:
      'Username must start with a letter and can only contain letters, numbers, underscores (_), and hyphens (-).',
  })
  @IsOptional()
  username?: string;

  @ApiProperty({
    example: 'StrongPass123!',
    minLength: 8,
    description: 'Hasło użytkownika',
  })
  @IsString()
  @MinLength(8)
  @IsOptional()
  password?: string;

  @ApiProperty({
    example: [Role.Admin],
    description: 'Rola użytkownika',
  })
  @IsOptional()
  roles?: string[];
}
