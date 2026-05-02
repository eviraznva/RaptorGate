import { BadRequestException, Body, Controller, Get, HttpCode, HttpStatus, Inject, Post } from '@nestjs/common';
import { ApiBody, ApiOperation } from '@nestjs/swagger';
import { Throttle } from '@nestjs/throttler';
import { ListIdentitySessionsUseCase } from '../../application/use-cases/list-identity-sessions.use-case.js';
import { RevokeIdentitySessionUseCase } from '../../application/use-cases/revoke-identity-session.use-case.js';
import { Permission } from '../../domain/enums/permissions.enum.js';
import { Role } from '../../domain/enums/role.enum.js';
import { ApiOkEnvelope } from '../decorators/api-envelope-response.decorator.js';
import {
  ApiError400,
  ApiError401,
  ApiError403,
  ApiError429,
  ApiError500,
} from '../decorators/api-error-response.decorator.js';
import { RequirePermissions } from '../decorators/auth/require-permissions.decorator.js';
import { Roles } from '../decorators/auth/roles.decorator.js';
import { ResponseMessage } from '../decorators/response-message.decorator.js';
import { RevokeIdentitySessionDto } from '../dtos/revoke-identity-session.dto.js';
import {
  ListIdentitySessionsResponseDto,
  RevokeIdentitySessionResponseDto,
} from '../dtos/identity-sessions-response.dto.js';

@Controller('identity-sessions')
export class IdentitySessionsController {
  constructor(
    @Inject(ListIdentitySessionsUseCase)
    private readonly listIdentitySessionsUseCase: ListIdentitySessionsUseCase,
    @Inject(RevokeIdentitySessionUseCase)
    private readonly revokeIdentitySessionUseCase: RevokeIdentitySessionUseCase,
  ) {}

  @Get()
  @ApiOperation({
    summary: 'List active identity sessions',
    description: 'Returns runtime identity sessions from the backend session store.',
  })
  @Roles(Role.Viewer)
  @RequirePermissions(Permission.IDENTITY_READ)
  @HttpCode(HttpStatus.OK)
  @ResponseMessage('Identity sessions retrieved')
  @ApiOkEnvelope(ListIdentitySessionsResponseDto, 'Identity sessions retrieved')
  @ApiError401('Access token is missing, invalid, or expired')
  @ApiError403('Insufficient permissions to view identity sessions')
  @ApiError429('Too many requests')
  @ApiError500('Internal server error while retrieving identity sessions')
  async list(): Promise<ListIdentitySessionsResponseDto> {
    return this.listIdentitySessionsUseCase.execute();
  }

  @Post('revoke')
  @ApiOperation({
    summary: 'Revoke an identity session',
    description: 'Revokes a runtime identity session by session ID or client source IP.',
  })
  @Roles(Role.Admin, Role.SuperAdmin)
  @RequirePermissions(Permission.IDENTITY_UPDATE)
  @HttpCode(HttpStatus.OK)
  @Throttle({ default: { limit: 30, ttl: 60_000 } })
  @ApiBody({ type: RevokeIdentitySessionDto })
  @ResponseMessage('Identity session revoke processed')
  @ApiOkEnvelope(RevokeIdentitySessionResponseDto, 'Identity session revoke processed')
  @ApiError400('Validation failed or invalid source IP')
  @ApiError401('Access token is missing, invalid, or expired')
  @ApiError403('Insufficient permissions to revoke identity sessions')
  @ApiError429('Too many requests')
  @ApiError500('Internal server error while revoking identity session')
  async revoke(
    @Body() dto: RevokeIdentitySessionDto,
  ): Promise<RevokeIdentitySessionResponseDto> {
    if (!dto.sessionId && !dto.sourceIp) {
      throw new BadRequestException('sessionId or sourceIp is required');
    }
    return this.revokeIdentitySessionUseCase.execute({
      sessionId: dto.sessionId,
      sourceIp: dto.sourceIp,
    });
  }
}
