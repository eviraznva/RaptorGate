export class AuthenticateIdentityResponseDto {
  sessionId: string;
  username: string;
  sourceIp: string;
  authenticatedAt: Date;
  expiresAt: Date;
}
