import { Controller, Get, HttpCode, HttpStatus, Inject } from '@nestjs/common';
import { ApiOperation } from '@nestjs/swagger';
import { GetTcpSessionsUseCase } from '../../application/use-cases/get-tcp-sessions.use-case.js';
import { Permission } from '../../domain/enums/permissions.enum.js';
import { Role } from '../../domain/enums/role.enum.js';
import { ApiOkEnvelope } from '../decorators/api-envelope-response.decorator.js';
import {
  ApiError401,
  ApiError403,
  ApiError429,
  ApiError500,
} from '../decorators/api-error-response.decorator.js';
import { RequirePermissions } from '../decorators/auth/require-permissions.decorator.js';
import { Roles } from '../decorators/auth/roles.decorator.js';
import { ResponseMessage } from '../decorators/response-message.decorator.js';
import { GetTcpSessionsResponseDto } from '../dtos/get-tcp-sessions-response.dto.js';
import { TcpTrackedSessionResponseMapper } from '../mappers/tcp-tracked-session-response.mapper.js';

@Controller('tcp-sessions')
export class TcpSessionsController {
  constructor(
    @Inject(GetTcpSessionsUseCase)
    private readonly getTcpSessionsUseCase: GetTcpSessionsUseCase,
  ) {}

  @Get()
  @ApiOperation({
    summary: 'Get TCP tracked sessions',
    description: 'Gets TCP tracked sessions from firewall gRPC query service',
  })
  @Roles(Role.Viewer)
  @RequirePermissions(Permission.FIREWALL_STATUS)
  @HttpCode(HttpStatus.OK)
  @ResponseMessage('TCP sessions retrieved')
  @ApiOkEnvelope(GetTcpSessionsResponseDto, 'TCP sessions retrieved')
  @ApiError401('Access token is missing, invalid, or expired')
  @ApiError403('Insufficient permissions to view TCP sessions')
  @ApiError429('Too many requests')
  @ApiError500('Internal server error while retrieving TCP sessions')
  async getTcpSessions(): Promise<GetTcpSessionsResponseDto> {
    const result = await this.getTcpSessionsUseCase.execute();

    const tcpSessions = result.tcpSessions.map((tcpSession) =>
      TcpTrackedSessionResponseMapper.toDto(tcpSession),
    );

    return { tcpSessions };
  }
}
