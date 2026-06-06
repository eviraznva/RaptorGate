import { ApiProperty } from '@nestjs/swagger';
import { Type } from 'class-transformer';
import { IsIP, IsInt, IsNotEmpty, IsOptional, IsString, Max, MaxLength, Min } from 'class-validator';

export class DecryptionExclusionQueryDto {
  @ApiProperty({
    description: 'Domain or SNI of the TLS target',
    example: 'api.example.com',
  })
  @IsString()
  @IsNotEmpty()
  @MaxLength(253)
  domain: string;

  @ApiProperty({
    description: 'Optional server IP of the TLS target',
    example: '142.250.203.36',
    required: false,
  })
  @IsOptional()
  @IsIP()
  serverIp?: string;

  @ApiProperty({
    description: 'Optional server port of the TLS target, defaults to 443',
    example: 443,
    required: false,
  })
  @IsOptional()
  @Type(() => Number)
  @IsInt()
  @Min(1)
  @Max(65535)
  serverPort?: number;
}
