import { ApiProperty } from '@nestjs/swagger';

export class IdentitySessionListItemResponseDto {
  @ApiProperty()
  sessionId: string;

  @ApiProperty()
  sourceIp: string;

  @ApiProperty()
  username: string;

  @ApiProperty({ type: [String] })
  groups: string[];

  @ApiProperty()
  createdAt: Date;

  @ApiProperty()
  expiresAt: Date;
}

export class ListIdentitySessionsResponseDto {
  @ApiProperty({ type: [IdentitySessionListItemResponseDto] })
  identitySessions: IdentitySessionListItemResponseDto[];
}

export class RevokeIdentitySessionResponseDto {
  @ApiProperty()
  removed: boolean;
}
