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
import { RequirePermissions } from 'src/infrastructure/decorators/require-permissions.decorator';
import { GetAllZonesUseCase } from 'src/application/use-cases/get-all-zones.use-case';
import { ExtractToken } from 'src/infrastructure/decorators/extract-token.decorator';
import { DeleteZoneUseCase } from 'src/application/use-cases/delete-zone.use-case';
import { CreateZoneUseCase } from 'src/application/use-cases/create-zone.use-case';
import { EditZoneUseCase } from 'src/application/use-cases/edit-zone.use-case';
import { Roles } from 'src/infrastructure/decorators/roles.decorator';
import { Permission } from 'src/domain/enums/permissions.enum';
import { CreateZoneDto } from '../dtos/create-zone.dto';
import { Zone } from 'src/domain/entities/zone.entity';
import { EditZoneDto } from '../dtos/edit-zone.dto';
import { Role } from 'src/domain/enums/role.enum';
import { ApiOperation } from '@nestjs/swagger';

@Controller('zones')
export class ZoneController {
  constructor(
    @Inject(CreateZoneUseCase)
    private readonly createZoneUseCase: CreateZoneUseCase,
    @Inject(GetAllZonesUseCase)
    private readonly getAllZonesUseCase: GetAllZonesUseCase,
    @Inject(EditZoneUseCase) private readonly editZoneUseCase: EditZoneUseCase,
    @Inject(DeleteZoneUseCase)
    private readonly deleteZoneUseCase: DeleteZoneUseCase,
  ) {}

  @Post()
  @ApiOperation({
    summary: 'Create a new zone',
    description: 'Creates a new zone with the provided name and description',
  })
  @Roles(Role.Operator)
  @RequirePermissions(Permission.ZONES_CREATE)
  async createZone(
    @Body() zoneDto: CreateZoneDto,
    @ExtractToken() accessToken: string,
  ): Promise<void> {
    await this.createZoneUseCase.execute({
      name: zoneDto.name,
      description: zoneDto.description || null,
      isActive: zoneDto.isActive,
      accessToken,
    });
  }

  @Get()
  @ApiOperation({
    summary: 'Get all zones',
    description: 'Gets a list of all zones with their details',
  })
  @Roles(Role.Viewer)
  @RequirePermissions(Permission.ZONES_READ)
  async getAllZones(): Promise<Zone[]> {
    const { zones } = await this.getAllZonesUseCase.execute();
    return zones;
  }

  @Put(':id')
  @ApiOperation({
    summary: "Edit a zone's details",
    description:
      'Edits the details of an existing zone, such as name, description, and active status',
  })
  @Roles(Role.Operator)
  @RequirePermissions(Permission.ZONES_UPDATE)
  async editZone(
    @Body() dto: EditZoneDto,
    @ExtractToken() accessToken: string,
    @Param('id') id: string,
  ): Promise<Zone> {
    const updatedZone = await this.editZoneUseCase.execute({
      ...dto,
      accessToken,
      id,
    });

    return updatedZone.zone;
  }

  @Delete(':id')
  @ApiOperation({
    summary: 'Delete a zone',
    description: 'Deletes an existing zone by its ID',
  })
  @Roles(Role.Operator)
  @RequirePermissions(Permission.ZONES_DELETE)
  async deleteZone(@Param('id') id: string) {
    await this.deleteZoneUseCase.execute(id);
  }
}
