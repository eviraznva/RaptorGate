import { ApiPropertyOptional } from '@nestjs/swagger';
import { IsIP, IsOptional, IsString } from 'class-validator';

export class RevokeIdentitySessionDto {
  @ApiPropertyOptional()
  @IsOptional()
  @IsString()
  sessionId?: string;

  @ApiPropertyOptional()
  @IsOptional()
  @IsIP()
  sourceIp?: string;
}
