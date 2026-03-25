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
import { Roles } from 'src/infrastructure/decorators/roles.decorator';
import { RequirePermissions } from 'src/infrastructure/decorators/require-permissions.decorator';
import { GetAllZonePairsUseCase } from 'src/application/use-cases/get-all-zone-pairs.use-case';
import { CreateZonePairUseCase } from 'src/application/use-cases/create-zone-pair.use-case';
import { DeleteZonePairUseCase } from 'src/application/use-cases/delete-zone-pair.use-case';
import { EditZonePairUseCase } from 'src/application/use-cases/edit-zone-pair.use-case';
import { ExtractToken } from 'src/infrastructure/decorators/extract-token.decorator';
import { CreateZonePairDto } from '../dtos/create-zone-pair.dto';
import { Permission } from 'src/domain/enums/permissions.enum';
import { EditZonePairDto } from '../dtos/edit-zone-pair.dto';
import { Role } from 'src/domain/enums/role.enum';
import { ApiOperation } from '@nestjs/swagger';
import { ZonePair } from 'src/domain/entities/zone-pair.entity';

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
