export type TokenPayload = {
  sub: string;
  username: string;
  principalType?: 'local_user' | 'external_admin';
  roles?: string[];
  authProvider?: 'local' | 'radius' | 'ldap';
  authProfileId?: string;
  externalId?: string;
};

export type TokenPair = {
  accessToken: string;
  refreshToken: string;
};

export interface ITokenService {
  generateAccessToken(payload: TokenPayload): Promise<string>;
  generateRefreshToken(): string;
  generateTokenPair(payload: TokenPayload): Promise<TokenPair>;
  verifyAccessToken(
    token: string,
    ignoreExpiration?: boolean,
  ): Promise<TokenPayload | null>;
  decodeAccessToken(token: string): TokenPayload | null;
}

export const TOKEN_SERVICE_TOKEN = Symbol('TOKEN_SERVICE_TOKEN');
