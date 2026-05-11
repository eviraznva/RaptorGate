import {
  Controller,
  Get,
  HttpCode,
  HttpStatus,
  Inject,
  Query,
} from '@nestjs/common';
import { ApiOperation } from '@nestjs/swagger';
import {
  type IPinningObservabilityService,
  PINNING_OBSERVABILITY_SERVICE_TOKEN,
} from '../../application/ports/pinning-observability-service.interface.js';
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
import { PinningBypassQueryDto } from '../dtos/pinning-bypass-query.dto.js';
import { PinningBypassResponseDto } from '../dtos/pinning-bypass-response.dto.js';
import { PinningStatsResponseDto } from '../dtos/pinning-stats-response.dto.js';

@Controller('pinning')
export class PinningController {
  constructor(
    @Inject(PINNING_OBSERVABILITY_SERVICE_TOKEN)
    private readonly service: IPinningObservabilityService,
  ) {}

  @Get('stats')
  @ApiOperation({
    summary: 'Get pinning detector stats',
    description:
      'Returns counters of active auto-bypass entries and tracked failure windows',
  })
  @Roles(Role.Viewer)
  @RequirePermissions(Permission.FIREWALL_STATUS)
  @HttpCode(HttpStatus.OK)
  @ResponseMessage('Pinning stats retrieved')
  @ApiOkEnvelope(PinningStatsResponseDto, 'Pinning stats retrieved')
  @ApiError401('Access token is missing, invalid, or expired')
  @ApiError403('Insufficient permissions')
  @ApiError429('Too many requests')
  @ApiError500('Internal server error')
  async getStats(): Promise<PinningStatsResponseDto> {
    return this.service.getStats();
  }

  @Get('bypass')
  @ApiOperation({
    summary: 'Inspect an auto-bypass entry',
    description:
      'Returns the bypass state for a given (source_ip, domain) pair, if present',
  })
  @Roles(Role.Viewer)
  @RequirePermissions(Permission.FIREWALL_STATUS)
  @HttpCode(HttpStatus.OK)
  @ResponseMessage('Pinning bypass retrieved')
  @ApiOkEnvelope(PinningBypassResponseDto, 'Pinning bypass retrieved')
  @ApiError400('Validation failed')
  @ApiError401('Access token is missing, invalid, or expired')
  @ApiError403('Insufficient permissions')
  @ApiError429('Too many requests')
  @ApiError500('Internal server error')
  async getBypass(
    @Query() query: PinningBypassQueryDto,
  ): Promise<PinningBypassResponseDto> {
    return this.service.getBypass(query.sourceIp, query.domain);
  }
}
