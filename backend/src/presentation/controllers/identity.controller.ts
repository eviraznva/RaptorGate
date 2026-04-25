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

// Endpointy identity dla portalu/captive sa publiczne, bo uzytkownik nie ma JWT admina.
// sourceIp pochodzi z TCP peer albo z XFF od lokalnego proxy.
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
    const peerIp = this.normalizeIp(req.socket?.remoteAddress ?? '');
    if (!peerIp) {
      throw new BadRequestException('Cannot resolve client source IP');
    }

    if (this.isTrustedProxyPeer(peerIp)) {
      const forwardedIp = this.resolveForwardedFor(req.headers['x-forwarded-for']);
      if (forwardedIp) return forwardedIp;
    }

    return peerIp;
  }

  private resolveForwardedFor(header: string | string[] | undefined): string | null {
    const raw = Array.isArray(header) ? header[header.length - 1] : header;
    if (!raw) return null;

    const values = raw
      .split(',')
      .map((value) => this.normalizeIp(value))
      .filter((value) => value.length > 0);

    return values[values.length - 1] ?? null;
  }

  private normalizeIp(raw: string): string {
    const value = raw.trim();
    return value.startsWith('::ffff:') ? value.slice('::ffff:'.length) : value;
  }

  private isTrustedProxyPeer(ip: string): boolean {
    return ip === '127.0.0.1' || ip === '::1';
  }
}
