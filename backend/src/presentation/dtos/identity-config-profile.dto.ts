import { ApiProperty, ApiPropertyOptional } from '@nestjs/swagger';
import {
  IsBoolean,
  IsArray,
  IsIn,
  IsInt,
  IsIP,
  IsNotEmpty,
  IsOptional,
  IsString,
  Matches,
  Max,
  MaxLength,
  Min,
  ValidateNested,
  ValidateIf,
} from 'class-validator';
import { Type } from 'class-transformer';

export class CreateRadiusServerProfileDto {
  @ApiProperty()
  @IsNotEmpty()
  @IsString()
  name: string;

  @ApiPropertyOptional({ nullable: true })
  @IsOptional()
  @IsString()
  description?: string | null;

  @ApiProperty()
  @IsBoolean()
  isActive: boolean;

  @ApiProperty()
  @IsNotEmpty()
  @IsString()
  host: string;

  @ApiProperty()
  @IsInt()
  @Min(1)
  @Max(65535)
  port: number;

  @ApiProperty()
  @IsNotEmpty()
  @IsString()
  sharedSecretRef: string;

  @ApiProperty()
  @IsInt()
  @Min(1)
  timeoutMs: number;

  @ApiProperty()
  @IsInt()
  @Min(0)
  retries: number;

  @ApiPropertyOptional({ nullable: true })
  @IsOptional()
  @IsString()
  nasIp?: string | null;

  @ApiPropertyOptional({ nullable: true })
  @IsOptional()
  @IsString()
  nasIdentifier?: string | null;

  @ApiPropertyOptional({ nullable: true })
  @IsOptional()
  @IsString()
  calledStationId?: string | null;
}

export class UpdateRadiusServerProfileDto extends CreateRadiusServerProfileDto {}

export class CreateLdapServerProfileDto {
  @ApiProperty()
  @IsNotEmpty()
  @IsString()
  name: string;

  @ApiPropertyOptional({ nullable: true })
  @IsOptional()
  @IsString()
  description?: string | null;

  @ApiProperty()
  @IsBoolean()
  isActive: boolean;

  @ApiProperty()
  @IsNotEmpty()
  @IsString()
  host: string;

  @ApiProperty()
  @IsInt()
  @Min(1)
  @Max(65535)
  port: number;

  @ApiProperty({ enum: ['disabled', 'starttls', 'ldaps'] })
  @IsIn(['disabled', 'starttls', 'ldaps'])
  tlsMode: 'disabled' | 'starttls' | 'ldaps';

  @ApiProperty()
  @IsNotEmpty()
  @IsString()
  bindDn: string;

  @ApiProperty()
  @IsNotEmpty()
  @IsString()
  bindPasswordRef: string;

  @ApiProperty()
  @IsNotEmpty()
  @IsString()
  userBaseDn: string;

  @ApiProperty()
  @IsNotEmpty()
  @IsString()
  userFilterAttribute: string;

  @ApiProperty()
  @IsNotEmpty()
  @IsString()
  groupBaseDn: string;

  @ApiProperty()
  @IsNotEmpty()
  @IsString()
  groupMemberAttribute: string;

  @ApiProperty()
  @IsNotEmpty()
  @IsString()
  groupNameAttribute: string;

  @ApiProperty()
  @IsInt()
  @Min(1)
  timeoutMs: number;

  @ApiProperty()
  @IsInt()
  @Min(1)
  cacheTtlSeconds: number;
}

export class UpdateLdapServerProfileDto extends CreateLdapServerProfileDto {}

export class CreateIdentityAuthenticationProfileDto {
  @ApiProperty()
  @IsNotEmpty()
  @IsString()
  name: string;

  @ApiPropertyOptional({ nullable: true })
  @IsOptional()
  @IsString()
  description?: string | null;

  @ApiProperty()
  @IsBoolean()
  isActive: boolean;

  @ApiProperty({ enum: ['radius', 'ldap', 'local'] })
  @IsIn(['radius', 'ldap', 'local'])
  provider: 'radius' | 'ldap' | 'local';

  @ApiPropertyOptional({ nullable: true })
  @IsOptional()
  @IsString()
  radiusProfileId?: string | null;

  @ApiPropertyOptional({ nullable: true })
  @IsOptional()
  @IsString()
  ldapProfileId?: string | null;

  @ApiProperty({ enum: ['none', 'ldap', 'radius_vsa'] })
  @IsIn(['none', 'ldap', 'radius_vsa'])
  groupSource: 'none' | 'ldap' | 'radius_vsa';

  @ApiProperty()
  @IsInt()
  @Min(1)
  sessionTtlSeconds: number;

  @ApiPropertyOptional({ type: () => [AdminRoleMappingDto] })
  @IsOptional()
  @IsArray()
  @ValidateNested({ each: true })
  @Type(() => AdminRoleMappingDto)
  adminRoleMappings?: AdminRoleMappingDto[];
}

export class UpdateIdentityAuthenticationProfileDto extends CreateIdentityAuthenticationProfileDto {}

export class AdminRoleMappingDto {
  @ApiProperty({ enum: ['username', 'ldap_group', 'radius_vsa'] })
  @IsIn(['username', 'ldap_group', 'radius_vsa'])
  matchType: 'username' | 'ldap_group' | 'radius_vsa';

  @ApiProperty()
  @IsNotEmpty()
  @IsString()
  matchValue: string;

  @ApiProperty({ enum: ['super_admin', 'admin', 'operator', 'viewer'] })
  @IsIn(['super_admin', 'admin', 'operator', 'viewer'])
  role: 'super_admin' | 'admin' | 'operator' | 'viewer';
}

export class PortalListenerSettingsDto {
  @ApiPropertyOptional()
  @IsOptional()
  @IsBoolean()
  enabled?: boolean;

  @ApiPropertyOptional({ nullable: true })
  @IsOptional()
  @ValidateIf((_, value) => value !== null)
  @MaxLength(64)
  @Matches(/^[A-Za-z0-9_.:-]+$/)
  interfaceName?: string | null;

  @ApiPropertyOptional({ nullable: true })
  @IsOptional()
  @ValidateIf((_, value) => value !== null)
  @Matches(/^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i)
  zoneId?: string | null;

  @ApiPropertyOptional({ nullable: true })
  @IsOptional()
  @ValidateIf((_, value) => value !== null)
  @IsIP()
  bindAddress?: string | null;

  @ApiPropertyOptional()
  @IsOptional()
  @IsInt()
  @Min(1)
  @Max(65535)
  bindPort?: number;
}

export class UpdateIdentitySettingsDto {
  @ApiPropertyOptional({ nullable: true })
  @IsOptional()
  @IsString()
  portalAuthenticationProfileId?: string | null;

  @ApiPropertyOptional({ nullable: true })
  @IsOptional()
  @IsString()
  adminAuthenticationProfileId?: string | null;

  @ApiPropertyOptional({ type: () => PortalListenerSettingsDto })
  @IsOptional()
  @ValidateNested()
  @Type(() => PortalListenerSettingsDto)
  portalListener?: PortalListenerSettingsDto;
}
