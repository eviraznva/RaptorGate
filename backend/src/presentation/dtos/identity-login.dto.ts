import { ApiProperty } from '@nestjs/swagger';
import { IsNotEmpty, IsString, MaxLength, MinLength } from 'class-validator';

// Body loginu identity. UWAGA: nie ma tu sourceIp — bierzemy go z connection
// (req.ip), zeby klient nie mogl podszyc IP z body (Issue 3 wymaganie).
export class IdentityLoginDto {
  @ApiProperty({ example: 'user' })
  @IsNotEmpty()
  @IsString()
  @MinLength(1)
  @MaxLength(64)
  username: string;

  @ApiProperty({ example: 'user123' })
  @IsNotEmpty()
  @IsString()
  @MaxLength(128)
  password: string;
}
