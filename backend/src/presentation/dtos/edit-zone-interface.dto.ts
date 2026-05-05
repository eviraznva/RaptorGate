import { ApiProperty } from '@nestjs/swagger';
import {
  IsBoolean,
  IsInt,
  IsIP,
  IsOptional,
  Matches,
  Max,
  Min,
  ValidateIf,
} from 'class-validator';

export class EditZoneInterfaceDto {
  @ApiProperty({
    example: '00000000-0000-0000-0000-000000000000',
    required: false,
  })
  @IsOptional()
  @Matches(/^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i)
  zoneId?: string;

  @ApiProperty({ example: 20, required: false, nullable: true })
  @IsOptional()
  @ValidateIf((_, value) => value !== null)
  @IsInt()
  @Min(1)
  @Max(4094)
  vlanId?: number | null;

  @ApiProperty({ example: '192.168.20.1', required: false, nullable: true })
  @IsOptional()
  @ValidateIf((_, value) => value !== null)
  @IsIP(4)
  ipv4Address?: string | null;

  @ApiProperty({ example: 24, required: false, nullable: true })
  @IsOptional()
  @ValidateIf((_, value) => value !== null)
  @IsInt()
  @Min(0)
  @Max(32)
  ipv4Mask?: number | null;

  @ApiProperty({ example: 'fd00:20::1', required: false, nullable: true })
  @IsOptional()
  @ValidateIf((_, value) => value !== null)
  @IsIP(6)
  ipv6Address?: string | null;

  @ApiProperty({ example: 64, required: false, nullable: true })
  @IsOptional()
  @ValidateIf((_, value) => value !== null)
  @IsInt()
  @Min(0)
  @Max(128)
  ipv6Mask?: number | null;

  @ApiProperty({ example: true, required: false })
  @IsOptional()
  @IsBoolean()
  isActive?: boolean;
}
