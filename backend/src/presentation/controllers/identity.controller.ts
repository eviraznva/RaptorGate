import {
  BadRequestException,
  Body,
  Controller,
  HttpCode,
  HttpStatus,
  Inject,
  Post,
  Req,
} from '@nestjs/common';
import { ApiBody, ApiOperation, ApiTags } from '@nestjs/swagger';
import { Throttle } from '@nestjs/throttler';
import type { Request } from 'express';
import { AuthenticateIdentityUseCase } from '../../application/use-cases/authenticate-identity.use-case.js';
import { LogoutIdentityUseCase } from '../../application/use-cases/logout-identity.use-case.js';
import { IsPublic } from '../../infrastructure/decorators/public.decorator.js';
import {
  ApiCreatedEnvelope,
  ApiOkEnvelope,
} from '../decorators/api-envelope-response.decorator.js';
import {
  ApiError400,
  ApiError401,
  ApiError429,
  ApiError500,
} from '../decorators/api-error-response.decorator.js';
import { ResponseMessage } from '../decorators/response-message.decorator.js';
import { IdentityLoginDto } from '../dtos/identity-login.dto.js';
import { IdentityLoginResponseDto } from '../dtos/identity-login-response.dto.js';
import { IdentityLogoutResponseDto } from '../dtos/identity-logout-response.dto.js';

// Endpointy identity dla portalu/captive (Issue 3). Login i logout sa publiczne
// — uzytkownik koncowy nie ma jeszcze JWT-a backendowego (to admin panel).
// sourceIp bierzemy z req.ip (express trust proxy = 1, ustawione w main.ts).
@ApiTags('Identity')
@Controller('identity')
export class IdentityController {
  constructor(
    @Inject(AuthenticateIdentityUseCase)
    private readonly authenticateIdentityUseCase: AuthenticateIdentityUseCase,
    @Inject(LogoutIdentityUseCase)
    private readonly logoutIdentityUseCase: LogoutIdentityUseCase,
  ) {}

  @ApiOperation({
    summary: 'Identity login (RADIUS)',
    description:
      'Authenticates end user via RADIUS provider. Source IP is taken from the connection, not from the request body. On success, creates a runtime identity session and synchronizes it to the firewall.',
  })
  @IsPublic()
  @Post('login')
  @HttpCode(HttpStatus.CREATED)
  @ApiBody({ type: IdentityLoginDto })
  @ResponseMessage('Identity session created')
  @ApiCreatedEnvelope(IdentityLoginResponseDto, 'Identity session created')
  @ApiError400('Validation failed or invalid source IP')
  @ApiError401('RADIUS rejected credentials')
  @ApiError429('Too many login attempts')
  @ApiError500()
  @Throttle({ default: { limit: 5, ttl: 60_000 } })
  async login(
    @Body() dto: IdentityLoginDto,
    @Req() req: Request,
  ): Promise<IdentityLoginResponseDto> {
    const sourceIp = this.resolveSourceIp(req);
    const result = await this.authenticateIdentityUseCase.execute({
      username: dto.username,
      password: dto.password,
      sourceIp,
    });

    return {
      sessionId: result.sessionId,
      username: result.username,
      sourceIp: result.sourceIp,
      authenticatedAt: result.authenticatedAt,
      expiresAt: result.expiresAt,
    };
  }

  @ApiOperation({
    summary: 'Identity logout',
    description:
      'Removes runtime identity session keyed by source IP and revokes it on the firewall. Tolerates missing session.',
  })
  @IsPublic()
  @Post('logout')
  @HttpCode(HttpStatus.OK)
  @ResponseMessage('Identity session revoked')
  @ApiOkEnvelope(IdentityLogoutResponseDto, 'Identity session revoked')
  @ApiError400('Invalid source IP')
  @ApiError429('Too many logout attempts')
  @ApiError500()
  @Throttle({ default: { limit: 10, ttl: 60_000 } })
  async logout(@Req() req: Request): Promise<IdentityLogoutResponseDto> {
    const sourceIp = this.resolveSourceIp(req);
    return this.logoutIdentityUseCase.execute({ sourceIp });
  }

  private resolveSourceIp(req: Request): string {
    // express.trust proxy=1 daje czysty req.ip; gdy brak — fallback na remoteAddress.
    const raw = req.ip ?? req.socket?.remoteAddress ?? '';
    if (!raw) {
      throw new BadRequestException('Cannot resolve client source IP');
    }
    // IPv4-mapped IPv6 (::ffff:1.2.3.4) — ucinamy prefix do IPv4 literal,
    // bo firewall trzyma sesje per IPv4 zgodnie z labem (192.168.20.0/24).
    return raw.startsWith('::ffff:') ? raw.slice('::ffff:'.length) : raw;
  }
}
