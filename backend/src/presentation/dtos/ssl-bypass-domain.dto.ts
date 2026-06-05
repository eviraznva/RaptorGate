import { ApiProperty, ApiPropertyOptional } from '@nestjs/swagger';
import { IsOptional, IsString, MaxLength, MinLength } from 'class-validator';

export class SslBypassDomainItemResponseDto {
  @ApiProperty({ example: '123e4567-e89b-12d3-a456-426614174000' })
  id: string;

  @ApiProperty({ example: 'www.google.com' })
  domain: string;

  @ApiProperty({ example: 'Manual TLS inspection bypass' })
  reason: string;

  @ApiProperty({ example: true })
  isActive: boolean;

  @ApiProperty({ example: '2026-06-05T10:00:00.000Z' })
  createdAt: string;
}

export class GetSslBypassDomainsResponseDto {
  @ApiProperty({ type: () => [SslBypassDomainItemResponseDto] })
  bypassDomains: SslBypassDomainItemResponseDto[];
}

export class CreateSslBypassDomainDto {
  @ApiProperty({ example: 'www.google.com', minLength: 1, maxLength: 255 })
  @IsString()
  @MinLength(1)
  @MaxLength(255)
  domain: string;

  @ApiPropertyOptional({
    example: 'Manual TLS inspection bypass',
    minLength: 1,
    maxLength: 255,
  })
  @IsString()
  @MinLength(1)
  @MaxLength(255)
  @IsOptional()
  reason?: string;
}

export class CreateSslBypassDomainResponseDto {
  @ApiProperty({ type: () => SslBypassDomainItemResponseDto })
  bypassDomain: SslBypassDomainItemResponseDto;
}
