import {
  ITokenService,
  TokenPair,
  TokenPayload,
} from 'src/application/ports/token-service.interface';
import { Env } from 'src/shared/config/env.validation';
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
    const accessToken = await this.jwtService.signAsync(payload);
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

  async verifyAccessToken(token: string): Promise<TokenPayload | null> {
    return await this.jwtService.verifyAsync<TokenPayload>(token, {
      secret: this.configService.get('JWT_SECRET'),
    });
  }
}
