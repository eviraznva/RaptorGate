import {
  ITokenService,
  TokenPair,
  TokenPayload,
} from '../../application/ports/token-service.interface';
import { Env } from '../../shared/config/env.validation';
import { ConfigService } from '@nestjs/config';
import { Injectable } from '@nestjs/common';
import { JwtService } from '@nestjs/jwt';

@Injectable()
export class TokenService implements ITokenService {
  constructor(
    private jwtService: JwtService,
    private readonly configService: ConfigService<Env, true>,
  ) {}

  async generateAccessToken(payload: TokenPayload): Promise<string> {
    const accessToken = await this.jwtService.signAsync(payload, {
      secret: this.configService.get('JWT_SECRET'),
      expiresIn: this.configService.get('JWT_EXPIRES_IN'),
    });
    return accessToken;
  }

  generateRefreshToken(): string {
    return crypto.randomUUID();
  }

  async generateTokenPair(payload: TokenPayload): Promise<TokenPair> {
    const accessToken = await this.generateAccessToken(payload);

    const refreshToken = this.generateRefreshToken();

    return { accessToken, refreshToken };
  }

  async verifyAccessToken(
    token: string,
    ignoreExpiration: boolean = false,
  ): Promise<TokenPayload | null> {
    return await this.jwtService.verifyAsync<TokenPayload>(token, {
      ignoreExpiration,
      secret: this.configService.get('JWT_SECRET'),
    });
  }

  decodeAccessToken(token: string): TokenPayload | null {
    return this.jwtService.decode<TokenPayload>(token);
  }
}
