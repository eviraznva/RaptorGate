import { ApiProperty } from '@nestjs/swagger';

export class RadiusServerProfileResponseDto {
  @ApiProperty()
  id: string;
  @ApiProperty()
  name: string;
  @ApiProperty({ nullable: true })
  description: string | null;
  @ApiProperty()
  isActive: boolean;
  @ApiProperty()
  host: string;
  @ApiProperty()
  port: number;
  @ApiProperty()
  sharedSecretRef: string;
  @ApiProperty()
  timeoutMs: number;
  @ApiProperty()
  retries: number;
  @ApiProperty({ nullable: true })
  nasIp: string | null;
  @ApiProperty({ nullable: true })
  nasIdentifier: string | null;
  @ApiProperty({ nullable: true })
  calledStationId: string | null;
  @ApiProperty()
  createdAt: Date;
  @ApiProperty()
  updatedAt: Date;
  @ApiProperty()
  createdBy: string;
}

export class LdapServerProfileResponseDto {
  @ApiProperty()
  id: string;
  @ApiProperty()
  name: string;
  @ApiProperty({ nullable: true })
  description: string | null;
  @ApiProperty()
  isActive: boolean;
  @ApiProperty()
  host: string;
  @ApiProperty()
  port: number;
  @ApiProperty()
  tlsMode: string;
  @ApiProperty()
  bindDn: string;
  @ApiProperty()
  bindPasswordRef: string;
  @ApiProperty()
  userBaseDn: string;
  @ApiProperty()
  userFilterAttribute: string;
  @ApiProperty()
  groupBaseDn: string;
  @ApiProperty()
  groupMemberAttribute: string;
  @ApiProperty()
  groupNameAttribute: string;
  @ApiProperty()
  timeoutMs: number;
  @ApiProperty()
  cacheTtlSeconds: number;
  @ApiProperty()
  createdAt: Date;
  @ApiProperty()
  updatedAt: Date;
  @ApiProperty()
  createdBy: string;
}

export class IdentityAuthenticationProfileResponseDto {
  @ApiProperty()
  id: string;
  @ApiProperty()
  name: string;
  @ApiProperty({ nullable: true })
  description: string | null;
  @ApiProperty()
  isActive: boolean;
  @ApiProperty()
  provider: string;
  @ApiProperty({ nullable: true })
  radiusProfileId: string | null;
  @ApiProperty({ nullable: true })
  ldapProfileId: string | null;
  @ApiProperty()
  groupSource: string;
  @ApiProperty()
  sessionTtlSeconds: number;
  @ApiProperty()
  createdAt: Date;
  @ApiProperty()
  updatedAt: Date;
  @ApiProperty()
  createdBy: string;
}

export class IdentitySettingsResponseDto {
  @ApiProperty({ nullable: true })
  portalAuthenticationProfileId: string | null;
  @ApiProperty({ nullable: true })
  adminAuthenticationProfileId: string | null;
  @ApiProperty({ nullable: true })
  updatedAt: Date | null;
  @ApiProperty({ nullable: true })
  updatedBy: string | null;
}

export class IdentityConfigResponseDto {
  @ApiProperty({ type: [RadiusServerProfileResponseDto] })
  radiusServerProfiles: RadiusServerProfileResponseDto[];
  @ApiProperty({ type: [LdapServerProfileResponseDto] })
  ldapServerProfiles: LdapServerProfileResponseDto[];
  @ApiProperty({ type: [IdentityAuthenticationProfileResponseDto] })
  authenticationProfiles: IdentityAuthenticationProfileResponseDto[];
  @ApiProperty({ type: IdentitySettingsResponseDto })
  settings: IdentitySettingsResponseDto;
}
