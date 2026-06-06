import {
  Controller,
  Delete,
  Get,
  HttpCode,
  HttpStatus,
  Inject,
  Query,
} from '@nestjs/common';
import { ApiOperation } from '@nestjs/swagger';
import {
  type IDecryptionExclusionObservabilityService,
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
import { DecryptionExclusionQueryDto } from '../dtos/pinning-bypass-query.dto.js';
import {
  ClearDecryptionExclusionsResponseDto,
  DecryptionExclusionListResponseDto,
  DecryptionExclusionResponseDto,
} from '../dtos/pinning-bypass-response.dto.js';
import { DecryptionExclusionStatsResponseDto } from '../dtos/pinning-stats-response.dto.js';

@Controller('tls/decryption-exclusions')
export class DecryptionExclusionsController {
  constructor(
    @Inject(PINNING_OBSERVABILITY_SERVICE_TOKEN)
    private readonly service: IDecryptionExclusionObservabilityService,
  ) {}

  @Get('stats')
  @ApiOperation({
    summary: 'Get local TLS decryption exclusion stats',
    description:
      'Returns counters of active local exclusions and tracked failure windows',
  })
  @Roles(Role.Viewer)
  @RequirePermissions(Permission.FIREWALL_STATUS)
  @HttpCode(HttpStatus.OK)
  @ResponseMessage('TLS decryption exclusion stats retrieved')
  @ApiOkEnvelope(
    DecryptionExclusionStatsResponseDto,
    'TLS decryption exclusion stats retrieved',
  )
  @ApiError401('Access token is missing, invalid, or expired')
  @ApiError403('Insufficient permissions')
  @ApiError429('Too many requests')
  @ApiError500('Internal server error')
  async getStats(): Promise<DecryptionExclusionStatsResponseDto> {
    return this.service.getStats();
  }

  @Get()
  @ApiOperation({
    summary: 'List local TLS decryption exclusions',
    description: 'Returns currently active local exclusions created after TLS decryption failures',
  })
  @Roles(Role.Viewer)
  @RequirePermissions(Permission.FIREWALL_STATUS)
  @HttpCode(HttpStatus.OK)
  @ResponseMessage('TLS decryption exclusions retrieved')
  @ApiOkEnvelope(
    DecryptionExclusionListResponseDto,
    'TLS decryption exclusions retrieved',
  )
  @ApiError401('Access token is missing, invalid, or expired')
  @ApiError403('Insufficient permissions')
  @ApiError429('Too many requests')
  @ApiError500('Internal server error')
  async list(): Promise<DecryptionExclusionListResponseDto> {
    return { exclusions: await this.service.listExclusions() };
  }

  @Get('lookup')
  @ApiOperation({
    summary: 'Inspect a local TLS decryption exclusion',
    description: 'Returns the local exclusion state for a given TLS target, if present',
  })
  @Roles(Role.Viewer)
  @RequirePermissions(Permission.FIREWALL_STATUS)
  @HttpCode(HttpStatus.OK)
  @ResponseMessage('TLS decryption exclusion retrieved')
  @ApiOkEnvelope(
    DecryptionExclusionResponseDto,
    'TLS decryption exclusion retrieved',
  )
  @ApiError400('Validation failed')
  @ApiError401('Access token is missing, invalid, or expired')
  @ApiError403('Insufficient permissions')
  @ApiError429('Too many requests')
  @ApiError500('Internal server error')
  async getExclusion(
    @Query() query: DecryptionExclusionQueryDto,
  ): Promise<DecryptionExclusionResponseDto> {
    return this.service.getExclusion(query.domain, query.serverIp, query.serverPort);
  }

  @Delete()
  @ApiOperation({
    summary: 'Clear local TLS decryption exclusions',
    description: 'Removes currently active local TLS decryption exclusions',
  })
  @Roles(Role.Admin)
  @RequirePermissions(Permission.FIREWALL_STATUS)
  @HttpCode(HttpStatus.OK)
  @ResponseMessage('TLS decryption exclusions cleared')
  @ApiOkEnvelope(
    ClearDecryptionExclusionsResponseDto,
    'TLS decryption exclusions cleared',
  )
  @ApiError401('Access token is missing, invalid, or expired')
  @ApiError403('Insufficient permissions')
  @ApiError429('Too many requests')
  @ApiError500('Internal server error')
  async clear(): Promise<ClearDecryptionExclusionsResponseDto> {
    return this.service.clearExclusions();
  }
}
