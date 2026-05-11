export class GetIdentitySessionResponseDto {
  authenticated: boolean;
  sourceIp: string;
  sessionId?: string;
  username?: string;
  authenticatedAt?: Date;
  expiresAt?: Date;
  groups?: string[];
}
