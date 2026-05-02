export interface IdentitySessionListItemDto {
  sessionId: string;
  sourceIp: string;
  username: string;
  groups: string[];
  createdAt: Date;
  expiresAt: Date;
}

export interface ListIdentitySessionsDto {
  identitySessions: IdentitySessionListItemDto[];
}
