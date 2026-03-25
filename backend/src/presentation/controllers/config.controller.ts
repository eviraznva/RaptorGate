import { ApplyConfigSnapshotUseCase } from 'src/application/use-cases/apply-config-snapshot.use-case';
import { RequirePermissions } from 'src/infrastructure/decorators/require-permissions.decorator';
import { GetConfigHistoryUseCase } from 'src/application/use-cases/get-config-history.use-case';
import { GetConfigHistoryResponseDto } from '../dtos/get-config-history-response.dto';
import { ExtractToken } from 'src/infrastructure/decorators/extract-token.decorator';
import { ApplyConfigSnapshotDto } from '../dtos/apply-config-snapshot.dto';
import { Roles } from 'src/infrastructure/decorators/roles.decorator';
import { Body, Controller, Get, Inject, Post } from '@nestjs/common';
import { Permission } from 'src/domain/enums/permissions.enum';
import { Role } from 'src/domain/enums/role.enum';
import { ApiOperation } from '@nestjs/swagger';

@Controller('config')
export class ConfigController {
  constructor(
    @Inject(ApplyConfigSnapshotUseCase)
    private readonly applyConfigSnapshotUseCase: ApplyConfigSnapshotUseCase,
    @Inject(GetConfigHistoryUseCase)
    private readonly getConfigHistoryUseCase: GetConfigHistoryUseCase,
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
}
