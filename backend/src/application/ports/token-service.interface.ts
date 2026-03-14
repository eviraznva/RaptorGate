import { Role } from 'src/domain/enums/role.enum';

export type TokenPayload = {
  sub: string;
  username: string;
  role: Role;
};

export type TokenPair = {
  accessToken: string;
  refreshToken: string;
};

export interface ITokenService {
  generateAccessToken(payload: TokenPayload): Promise<string>;
  generateRefreshToken(): string;
  generateTokenPair(payload: TokenPayload): Promise<TokenPair>;
  verifyAccessToken(token: string): Promise<TokenPayload | null>;
}

export const TOKEN_SERVICE_TOKEN = Symbol('TOKEN_SERVICE_TOKEN');
