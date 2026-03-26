import { ApplyConfigSnapshotUseCase } from '../../application/use-cases/apply-config-snapshot.use-case.js';
import { RequirePermissions } from '../../infrastructure/decorators/require-permissions.decorator.js';
import { GetConfigHistoryUseCase } from '../../application/use-cases/get-config-history.use-case.js';
import { RollbackConfigUseCase } from '../../application/use-cases/rollback-config.use-case.js';
import { ExtractToken } from '../../infrastructure/decorators/extract-token.decorator.js';
import { GetConfigHistoryResponseDto } from '../dtos/get-config-history-response.dto.js';
import { ApplyConfigSnapshotDto } from '../dtos/apply-config-snapshot.dto.js';
import { Controller, Inject, Post, Body, Get, Param } from '@nestjs/common';
import { Roles } from '../../infrastructure/decorators/roles.decorator.js';
import { Permission } from '../../domain/enums/permissions.enum.js';
import { Role } from '../../domain/enums/role.enum.js';
import { ApiOperation } from '@nestjs/swagger';

@Controller('config')
export class ConfigController {
  constructor(
    @Inject(ApplyConfigSnapshotUseCase)
    private readonly applyConfigSnapshotUseCase: ApplyConfigSnapshotUseCase,
    @Inject(GetConfigHistoryUseCase)
    private readonly getConfigHistoryUseCase: GetConfigHistoryUseCase,
    @Inject(RollbackConfigUseCase)
    private readonly rollbackConfigUseCase: RollbackConfigUseCase,
  ) {}

  @ApiOperation({
    summary: 'Apply configuration snapshot',
    description:
      'Applies a configuration snapshot. This will replace the current active configuration with the one from the snapshot.',
  })
  @Roles(Role.Operator)
  @RequirePermissions(Permission.SNAPSHOTS_CREATE)
  @Post('apply')
  async applyConfigSnapshot(
    @Body() dto: ApplyConfigSnapshotDto,
    @ExtractToken() accessToken: string,
  ): Promise<void> {
    await this.applyConfigSnapshotUseCase.execute({ ...dto, accessToken });
  }

  @ApiOperation({
    summary: 'History of configuration snapshots',
    description:
      'Gets the history of all configuration snapshots, including active and inactive ones.',
  })
  @Roles(Role.Viewer)
  @Get('history')
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
  @Post('rollback/:id')
  async rollbackToConfigSnapshot(@Param('id') id: string): Promise<void> {
    await this.rollbackConfigUseCase.execute({ id });
  }
}
