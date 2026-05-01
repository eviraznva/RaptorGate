import { ApiProperty, ApiPropertyOptional } from '@nestjs/swagger';
import { IsNotEmpty, IsOptional, IsString } from 'class-validator';

export class TestRadiusProfileDto {
  @ApiProperty()
  @IsNotEmpty()
  @IsString()
  username: string;

  @ApiProperty()
  @IsNotEmpty()
  @IsString()
  password: string;

  @ApiPropertyOptional()
  @IsOptional()
  @IsString()
  callingStationId?: string;
}

export class TestLdapProfileDto {
  @ApiProperty()
  @IsNotEmpty()
  @IsString()
  username: string;
}

export class IdentityProviderTestResponseDto {
  @ApiProperty()
  result: string;

  @ApiProperty()
  latencyMs: number;

  @ApiProperty()
  message: string;

  @ApiPropertyOptional({ type: [String] })
  groups?: string[];

  @ApiPropertyOptional()
  userDn?: string;
}
