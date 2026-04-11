import type { TokenPayload } from '../../application/ports/token-service.interface.js';
import { Env } from '../../shared/config/env.validation.js';
import { ExtractJwt, Strategy } from 'passport-jwt';
import { PassportStrategy } from '@nestjs/passport';
import { ConfigService } from '@nestjs/config';
import { Injectable } from '@nestjs/common';

@Injectable()
export class JwtStrategy extends PassportStrategy(Strategy) {
  constructor(private readonly configService: ConfigService<Env, true>) {
    super({
      jwtFromRequest: ExtractJwt.fromAuthHeaderAsBearerToken(),
      ignoreExpiration: false,
      secretOrKey: configService.get('JWT_SECRET', {
        infer: true,
      }),
    });
  }

  validate(payload: TokenPayload) {
    return { id: payload.sub, username: payload.username };
  }
}
