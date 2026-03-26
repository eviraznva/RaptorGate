import {
  Body,
  Controller,
  Delete,
  Get,
  Inject,
  Param,
  Post,
  Put,
} from '@nestjs/common';
import { RequirePermissions } from '../../infrastructure/decorators/require-permissions.decorator.js';
import { GetAllZonePairsUseCase } from '../../application/use-cases/get-all-zone-pairs.use-case.js';
import { CreateZonePairUseCase } from '../../application/use-cases/create-zone-pair.use-case.js';
import { DeleteZonePairUseCase } from '../../application/use-cases/delete-zone-pair.use-case.js';
import { EditZonePairUseCase } from '../../application/use-cases/edit-zone-pair.use-case.js';
import { ExtractToken } from '../../infrastructure/decorators/extract-token.decorator.js';
import { Roles } from '../../infrastructure/decorators/roles.decorator.js';
import { ZonePair } from '../../domain/entities/zone-pair.entity.js';
import { CreateZonePairDto } from '../dtos/create-zone-pair.dto.js';
import { Permission } from '../../domain/enums/permissions.enum.js';
import { EditZonePairDto } from '../dtos/edit-zone-pair.dto.js';
import { Role } from '../../domain/enums/role.enum.js';
import { ApiOperation } from '@nestjs/swagger';

@Controller('zone-pairs')
export class ZonePairsController {
  constructor(
    @Inject(CreateZonePairUseCase)
    private readonly createZonePairUseCase: CreateZonePairUseCase,
    @Inject(GetAllZonePairsUseCase)
    private readonly getAllZonePairsUseCase: GetAllZonePairsUseCase,
    @Inject(DeleteZonePairUseCase)
    private readonly deleteZonePairUseCase: DeleteZonePairUseCase,
    @Inject(EditZonePairUseCase)
    private readonly editZonePairUseCase: EditZonePairUseCase,
  ) {}

  @ApiOperation({
    summary: 'Create a new zone pair',
    description:
      'creates a new zone pair with the provided origin and destination zone IDs',
  })
  @Post()
  @Roles(Role.Operator)
  @RequirePermissions(Permission.ZONE_PAIRINGS_CREATE)
  async createZonePair(
    @Body() dto: CreateZonePairDto,
    @ExtractToken() accessToken: string,
  ) {
    await this.createZonePairUseCase.execute({ ...dto, accessToken });
  }

  @ApiOperation({
    summary: 'Get all zone pairs',
    description: 'Gets a list of all zone pairs with their details',
  })
  @Get()
  @Roles(Role.Viewer)
  @RequirePermissions(Permission.ZONE_PAIRINGS_READ)
  async getAllZonePairs(): Promise<ZonePair[]> {
    const { zonePairs } = await this.getAllZonePairsUseCase.execute();

    return zonePairs;
  }

  @ApiOperation({
    summary: 'Edit an existing zone pair',
    description:
      'edits an existing zone pair with the provided details. At least one field must be provided for update',
  })
  @Put(':id')
  @Roles(Role.Operator)
  @RequirePermissions(Permission.ZONE_PAIRINGS_CREATE)
  async editZonePair(
    @Body() dto: EditZonePairDto,
    @Param('id') id: string,
    @ExtractToken() accessToken: string,
  ) {
    await this.editZonePairUseCase.execute({ ...dto, id, accessToken });
  }

  @ApiOperation({
    summary: 'Delete a zone pair',
    description: 'Deletes an existing zone pair by its ID',
  })
  @Delete(':id')
  @Roles(Role.Operator)
  @RequirePermissions(Permission.ZONE_PAIRINGS_DELETE)
  async deleteZonePair(@Param('id') id: string) {
    await this.deleteZonePairUseCase.execute({ id });
  }
}
