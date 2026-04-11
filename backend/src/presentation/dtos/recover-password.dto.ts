import {
  MinLength,
  MaxLength,
  Matches,
  IsNotEmpty,
  IsString,
  IsStrongPassword,
} from 'class-validator';
import { ApiProperty } from '@nestjs/swagger';

export class RecoveryPasswordDto {
  @ApiProperty({ example: 'jankowal' })
  @IsNotEmpty()
  @IsString()
  @MinLength(3)
  @MaxLength(20)
  @Matches(/^[a-zA-Z][a-zA-Z0-9_-]*$/, {
    message:
      'Username must start with a letter and can only contain letters, numbers, underscores (_), and hyphens (-).',
  })
  username: string;

  @ApiProperty({
    example: 'a3f9c1e7d4b2f0a8c6e4d2b0a9f7e5c3a1b9d7f5e3c1a8b6d4f2e0c8a6b4d2f0',
    description: 'Recovery token (hex)',
  })
  @IsNotEmpty()
  @IsString()
  @Matches(/^[a-f0-9]+$/i, {
    message: 'Recovery token must be a valid hex string.',
  })
  recoveryToken: string;

  @ApiProperty({
    example: 'StrongPass123!',
    minLength: 8,
    description: 'Nowe hasło użytkownika',
  })
  @IsStrongPassword(
    {
      minUppercase: 1,
      minLength: 8,
      minNumbers: 1,
      minSymbols: 1,
    },
    { message: 'Password is too simple' },
  )
  @IsNotEmpty()
  @IsString()
  @MinLength(8)
  newPassword: string;
}
