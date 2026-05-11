export interface RevokeIdentitySessionDto {
  sessionId?: string;
  sourceIp?: string;
}

export interface RevokeIdentitySessionResultDto {
  removed: boolean;
}
