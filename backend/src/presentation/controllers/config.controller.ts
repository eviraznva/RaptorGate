import {
  Body,
  Controller,
  Get,
  HttpCode,
  HttpStatus,
  Inject,
  Param,
  Post,
} from '@nestjs/common';
import { ApiBody, ApiOperation } from '@nestjs/swagger';
import { ApplyConfigSnapshotUseCase } from '../../application/use-cases/apply-config-snapshot.use-case.js';
import { ExportConfigUseCase } from '../../application/use-cases/export-config.use-case.js';
import { GetConfigHistoryUseCase } from '../../application/use-cases/get-config-history.use-case.js';
import { ImportConfigUseCase } from '../../application/use-cases/import-config.use-case.js';
import { RollbackConfigUseCase } from '../../application/use-cases/rollback-config.use-case.js';
import { Permission } from '../../domain/enums/permissions.enum.js';
import { Role } from '../../domain/enums/role.enum.js';
import { mapConfigSnapshotToPayloadRecord } from '../../infrastructure/persistence/mappers/config-payload.mapper.js';
import { ConfigurationSnapshotJsonMapper } from '../../infrastructure/persistence/mappers/configuration-snapshots.mapper.js';
import {
  ApiCreatedEnvelope,
  ApiOkEnvelope,
} from '../decorators/api-envelope-response.decorator.js';
import {
  ApiError400,
  ApiError401,
  ApiError403,
  ApiError429,
  ApiError500,
} from '../decorators/api-error-response.decorator.js';
import { ExtractToken } from '../decorators/auth/extract-token.decorator.js';
import { RequirePermissions } from '../decorators/auth/require-permissions.decorator.js';
import { Roles } from '../decorators/auth/roles.decorator.js';
import { ResponseMessage } from '../decorators/response-message.decorator.js';
import { ApplyConfigSnapshotDto } from '../dtos/apply-config-snapshot.dto.js';
import { ApplyConfigSnapshotResponseDto } from '../dtos/apply-config-snapshot-response.dto.js';
import { ExportConfigResponseDto } from '../dtos/export-config-response.dto.js';
import { GetConfigHistoryResponseDto } from '../dtos/get-config-history-response.dto.js';
import { ImportConfigSnapshotDto } from '../dtos/import-config-snapshot.dto.js';
import { RollbackConfigSnapshotResponseDto } from '../dtos/rollback-config-snapshot.dto.js';

@Controller('config')
export class ConfigController {
  constructor(
    @Inject(ApplyConfigSnapshotUseCase)
    private readonly applyConfigSnapshotUseCase: ApplyConfigSnapshotUseCase,
    @Inject(GetConfigHistoryUseCase)
    private readonly getConfigHistoryUseCase: GetConfigHistoryUseCase,
    @Inject(RollbackConfigUseCase)
    private readonly rollbackConfigUseCase: RollbackConfigUseCase,
    @Inject(ExportConfigUseCase)
    private readonly exportConfigUseCase: ExportConfigUseCase,
    @Inject(ImportConfigUseCase)
    private readonly importConfigUseCase: ImportConfigUseCase,
  ) {}

  @ApiOperation({
    summary: 'Apply configuration snapshot',
    description:
      'Applies a configuration snapshot. This will replace the current active configuration with the one from the snapshot.',
  })
  @Roles(Role.Operator)
  @RequirePermissions(Permission.SNAPSHOTS_CREATE)
  @Post('apply')
  @HttpCode(HttpStatus.CREATED)
  @ApiBody({ type: ApplyConfigSnapshotDto })
  @ResponseMessage('Configuration snapshot applied')
  @ApiCreatedEnvelope(
    ApplyConfigSnapshotResponseDto,
    'Configuration snapshot applied',
  )
  @ApiError400('Validation failed or invalid snapshot ID')
  @ApiError401('Access token is missing, invalid, or expired')
  @ApiError403('Insufficient permissions to apply configuration snapshot')
  @ApiError429('Too many requests')
  @ApiError500('Internal server error while applying configuration snapshot')
  async applyConfigSnapshot(
    @Body() dto: ApplyConfigSnapshotDto,
    @ExtractToken() accessToken: string,
  ): Promise<ApplyConfigSnapshotResponseDto> {
    const configSnapshot = await this.applyConfigSnapshotUseCase.execute({
      ...dto,
      accessToken,
    });

    return configSnapshot;
  }

  @ApiOperation({
    summary: 'History of configuration snapshots',
    description:
      'Gets the history of all configuration snapshots, including active and inactive ones.',
  })
  @Roles(Role.Viewer)
  @Get('history')
  @HttpCode(HttpStatus.OK)
  @ResponseMessage('Configuration snapshot history retrieved')
  @ApiOkEnvelope(
    GetConfigHistoryResponseDto,
    'Configuration snapshot history retrieved',
  )
  @ApiError401('Access token is missing, invalid, or expired')
  @ApiError403(
    'Insufficient permissions to view configuration snapshot history',
  )
  @ApiError429('Too many requests to retrieve configuration snapshot history')
  @ApiError500(
    'Internal server error while retrieving configuration snapshot history',
  )
  async getConfigHistory(): Promise<GetConfigHistoryResponseDto> {
    const configHistory = await this.getConfigHistoryUseCase.execute();
    return configHistory;
  }

  @ApiOperation({
    summary: 'Rollback to a chosen configuration snapshot',
    description:
      'Rolls back the active configuration to a chosen snapshot. This will replace the current active configuration with the one from the snapshot.',
  })
  @Roles(Role.Operator)
  @RequirePermissions(Permission.SNAPSHOTS_RESTORE)
  @Post('rollback/:id')
  @ResponseMessage('Configuration rolled back to chosen snapshot')
  @ApiCreatedEnvelope(
    RollbackConfigSnapshotResponseDto,
    'Configuration rolled back to chosen snapshot',
  )
  @ApiError400('Validation failed or invalid snapshot ID')
  @ApiError401('Access token is missing, invalid, or expired')
  @ApiError403('Insufficient permissions to rollback configuration snapshot')
  @ApiError429('Too many requests')
  @ApiError500(
    'Internal server error while rolling back configuration snapshot',
  )
  async rollbackToConfigSnapshot(
    @Param('id') id: string,
  ): Promise<RollbackConfigSnapshotResponseDto> {
    const config = await this.rollbackConfigUseCase.execute({ id });
    return config;
  }

  @ApiOperation({
    summary: 'Export active configuration snapshot',
    description:
      'Exports the active configuration snapshot. This will return the current active configuration in a format that can be saved or used for backup purposes.',
  })
  @Roles(Role.Admin, Role.SuperAdmin)
  @RequirePermissions(Permission.SNAPSHOTS_READ)
  @Get('export')
  @ResponseMessage('Active configuration snapshot exported')
  @ApiOkEnvelope(
    ExportConfigResponseDto,
    'Active configuration snapshot exported',
  )
  @ApiError401('Access token is missing, invalid, or expired')
  @ApiError403('Insufficient permissions to export configuration snapshot')
  @ApiError429('Too many requests')
  @ApiError500('Internal server error while exporting configuration snapshot')
  async exportConfig(): Promise<ExportConfigResponseDto> {
    const result = await this.exportConfigUseCase.execute();
    const configPayloadToRecord = mapConfigSnapshotToPayloadRecord(
      result.configSnapshot,
    );

    result.configSnapshot.setPayloadJson(configPayloadToRecord);
    const configSnapshot = ConfigurationSnapshotJsonMapper.toRecord(
      result.configSnapshot,
    );

    return configSnapshot;
  }

  @ApiOperation({
    summary: 'Import configuration snapshot',
    description:
      'Imports a configuration snapshot from a JSON payload. Validates checksum, updates internal tables if isActive=true and creates a new snapshot version.',
  })
  @Roles(Role.Operator)
  @RequirePermissions(Permission.SNAPSHOTS_CREATE)
  @Post('import')
  @HttpCode(HttpStatus.CREATED)
  @ApiBody({ type: ImportConfigSnapshotDto })
  @ResponseMessage('Configuration snapshot imported')
  @ApiCreatedEnvelope(
    ExportConfigResponseDto,
    'Configuration snapshot imported',
  )
  @ApiError400('Validation failed, bad format or checksum mismatch')
  @ApiError401('Access token is missing, invalid, or expired')
  @ApiError403('Insufficient permissions to import configuration snapshot')
  @ApiError429('Too many requests')
  @ApiError500('Internal server error while importing configuration snapshot')
  async importConfigSnapshot(
    @Body() dto: ImportConfigSnapshotDto,
    @ExtractToken() accessToken: string,
  ): Promise<ExportConfigResponseDto> {
    const result = await this.importConfigUseCase.execute({
      snapshotData: dto,
      accessToken,
    });

    const configPayloadToRecord = mapConfigSnapshotToPayloadRecord(
      result.configSnapshot,
    );

    result.configSnapshot.setPayloadJson(configPayloadToRecord);
    const configSnapshot = ConfigurationSnapshotJsonMapper.toRecord(
      result.configSnapshot,
    );

    return configSnapshot;
  }
}
