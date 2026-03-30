import {
  Body,
  Controller,
  Delete,
  Get,
  HttpCode,
  HttpStatus,
  Inject,
  Param,
  Post,
  Put,
} from '@nestjs/common';
import {
  ApiCreatedEnvelope,
  ApiNoContentEnvelope,
  ApiOkEnvelope,
} from '../decorators/api-envelope-response.decorator.js';
import {
  ApiError400,
  ApiError401,
  ApiError403,
  ApiError404,
  ApiError409,
  ApiError429,
  ApiError500,
} from '../decorators/api-error-response.decorator.js';
import { RequirePermissions } from '../../infrastructure/decorators/require-permissions.decorator.js';
import { GetAllZonePairsUseCase } from '../../application/use-cases/get-all-zone-pairs.use-case.js';
import { CreateZonePairUseCase } from '../../application/use-cases/create-zone-pair.use-case.js';
import { DeleteZonePairUseCase } from '../../application/use-cases/delete-zone-pair.use-case.js';
import { EditZonePairUseCase } from '../../application/use-cases/edit-zone-pair.use-case.js';
import { ExtractToken } from '../../infrastructure/decorators/extract-token.decorator.js';
import { CreateZonePairResponseDto } from '../dtos/create-zone-pair-response.dto.js';
import { EditZonePairResponseDto } from '../dtos/edit-zone-pair-response.dto.js';
import { ResponseMessage } from '../decorators/response-message.decorator.js';
import { Roles } from '../../infrastructure/decorators/roles.decorator.js';
import { ZonePair } from '../../domain/entities/zone-pair.entity.js';
import { CreateZonePairDto } from '../dtos/create-zone-pair.dto.js';
import { Permission } from '../../domain/enums/permissions.enum.js';
import { EditZonePairDto } from '../dtos/edit-zone-pair.dto.js';
import { ApiBody, ApiOperation } from '@nestjs/swagger';
import { Role } from '../../domain/enums/role.enum.js';

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
  @HttpCode(HttpStatus.CREATED)
  @ApiBody({ type: CreateZonePairDto })
  @ResponseMessage('Zone pair created')
  @ApiCreatedEnvelope(CreateZonePairResponseDto, 'Zone pair created')
  @ApiError400('Validation failed')
  @ApiError401('Authorization header missing or invalid')
  @ApiError403('Insufficient permissions')
  @ApiError404('Zone not found')
  @ApiError409('Zone pair already exists')
  @ApiError429('Too many requests')
  @ApiError500('Server error while creating zone pair')
  async createZonePair(
    @Body() dto: CreateZonePairDto,
    @ExtractToken() accessToken: string,
  ): Promise<CreateZonePairResponseDto> {
    const zonePair = await this.createZonePairUseCase.execute({
      ...dto,
      accessToken,
    });

    return zonePair;
  }

  @ApiOperation({
    summary: 'Get all zone pairs',
    description: 'Gets a list of all zone pairs with their details',
  })
  @Get()
  @Roles(Role.Viewer)
  @RequirePermissions(Permission.ZONE_PAIRINGS_READ)
  @HttpCode(HttpStatus.OK)
  @ResponseMessage('List of zone pairs retrieved')
  @ApiOkEnvelope(ZonePair, 'List of zone pairs retrieved')
  @ApiError401('Access token is missing, invalid, or expired')
  @ApiError403('Insufficient permissions to view zone pairs')
  @ApiError429('Too many requests')
  @ApiError500('Internal server error while retrieving zone pairs')
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
  @HttpCode(HttpStatus.OK)
  @ApiBody({ type: EditZonePairDto })
  @ResponseMessage('Zone pair updated')
  @ApiOkEnvelope(EditZonePairResponseDto, 'Zone pair updated')
  @ApiError400('Validation failed')
  @ApiError401('Access token is missing, invalid, or expired')
  @ApiError403('Insufficient permissions to edit zone pair')
  @ApiError404('Zone pair not found')
  @ApiError429('Too many requests')
  @ApiError500('Internal server error while editing zone pair')
  async editZonePair(
    @Body() dto: EditZonePairDto,
    @Param('id') id: string,
    @ExtractToken() accessToken: string,
  ): Promise<EditZonePairResponseDto> {
    const zonePair = await this.editZonePairUseCase.execute({
      ...dto,
      id,
      accessToken,
    });

    return zonePair;
  }

  @ApiOperation({
    summary: 'Delete a zone pair',
    description: 'Deletes an existing zone pair by its ID',
  })
  @Delete(':id')
  @Roles(Role.Operator)
  @RequirePermissions(Permission.ZONE_PAIRINGS_DELETE)
  @HttpCode(HttpStatus.NO_CONTENT)
  @ResponseMessage('Zone pair deleted')
  @ApiNoContentEnvelope()
  @ApiError401('Access token is missing, invalid, or expired')
  @ApiError403('Insufficient permissions to delete zone pair')
  @ApiError404('Zone pair not found')
  @ApiError429('Too many requests')
  @ApiError500('Internal server error while deleting zone pair')
  async deleteZonePair(@Param('id') id: string): Promise<void> {
    await this.deleteZonePairUseCase.execute({ id });
  }
}
