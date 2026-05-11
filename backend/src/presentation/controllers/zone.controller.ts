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
  Query,
} from "@nestjs/common";
import { ApiBody, ApiOperation } from "@nestjs/swagger";
import { CreateZoneUseCase } from "../../application/use-cases/create-zone.use-case.js";
import { DeleteZoneUseCase } from "../../application/use-cases/delete-zone.use-case.js";
import { EditZoneUseCase } from "../../application/use-cases/edit-zone.use-case.js";
import { GetAllZonesUseCase } from "../../application/use-cases/get-all-zones.use-case.js";
import { Permission } from "../../domain/enums/permissions.enum.js";
import { Role } from "../../domain/enums/role.enum.js";
import {
  ApiCreatedEnvelope,
  ApiNoContentEnvelope,
  ApiOkEnvelope,
} from "../decorators/api-envelope-response.decorator.js";
import {
  ApiError400,
  ApiError401,
  ApiError403,
  ApiError404,
  ApiError409,
  ApiError429,
  ApiError500,
} from "../decorators/api-error-response.decorator.js";
import { ExtractToken } from "../decorators/auth/extract-token.decorator.js";
import { RequirePermissions } from "../decorators/auth/require-permissions.decorator.js";
import { Roles } from "../decorators/auth/roles.decorator.js";
import { ResponseMessage } from "../decorators/response-message.decorator.js";
import { CreateZoneDto } from "../dtos/create-zone.dto.js";
import { CreateZoneResponseDto } from "../dtos/create-zone-response.dto.js";
import { EditZoneDto } from "../dtos/edit-zone.dto.js";
import { EditZoneResponseDto } from "../dtos/edit-zone-response.dto.js";
import { GetAllZonesResponseDto } from "../dtos/get-all-zones-response.dto.js";
import { GetZonesQueryDto } from "../dtos/get-zones-query.dto.js";
import { ZoneResponseMapper } from "../mappers/zone-response.mapper.js";

@Controller("zones")
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
    summary: "Create a new zone",
    description: "Creates a new zone with the provided name and description",
  })
  @Roles(Role.Operator)
  @RequirePermissions(Permission.ZONES_CREATE)
  @HttpCode(HttpStatus.CREATED)
  @ApiBody({ type: CreateZoneDto })
  @ResponseMessage("Zone created")
  @ApiCreatedEnvelope(CreateZoneResponseDto, "Zone created")
  @ApiError400("Validation failed")
  @ApiError401("Authorization header missing or invalid")
  @ApiError403("Insufficient permissions")
  @ApiError409("Zone already exists")
  @ApiError429("Too many requests")
  @ApiError500("Server error while creating zone")
  async createZone(
    @Body() zoneDto: CreateZoneDto,
    @ExtractToken() accessToken: string,
  ): Promise<CreateZoneResponseDto> {
    const result = await this.createZoneUseCase.execute({
      ...zoneDto,
      accessToken,
    });

    const zone = ZoneResponseMapper.toDto(result.zone);

    return { zone };
  }

  @Get()
  @ApiOperation({
    summary: "Get all zones",
    description: "Gets a list of all zones with their details",
  })
  @Roles(Role.Viewer)
  @RequirePermissions(Permission.ZONES_READ)
  @HttpCode(HttpStatus.OK)
  @ResponseMessage("List of zones retrieved")
  @ApiOkEnvelope(GetAllZonesResponseDto, "List of zones retrieved")
  @ApiError401("Access token is missing, invalid, or expired")
  @ApiError403("Insufficient permissions to view zones")
  @ApiError429("Too many requests")
  @ApiError500("Internal server error while retrieving zones")
  async getAllZones(
    @Query() query: GetZonesQueryDto,
  ): Promise<GetAllZonesResponseDto> {
    const result = await this.getAllZonesUseCase.execute(query);

    const zones = result.zones.map((zone) => ZoneResponseMapper.toDto(zone));

    return { zones };
  }

  @Put(":id")
  @ApiOperation({
    summary: "Edit a zone's details",
    description:
      "Edits the details of an existing zone, such as name, description, and active status",
  })
  @Roles(Role.Operator)
  @RequirePermissions(Permission.ZONES_UPDATE)
  @HttpCode(HttpStatus.OK)
  @ApiBody({ type: EditZoneDto })
  @ResponseMessage("Zone updated")
  @ApiOkEnvelope(EditZoneResponseDto, "Zone updated")
  @ApiError400("Validation failed")
  @ApiError401("Access token is missing, invalid, or expired")
  @ApiError403("Insufficient permissions to edit zone")
  @ApiError404("Zone not found")
  @ApiError429("Too many requests")
  @ApiError500("Internal server error while editing zone")
  async editZone(
    @Body() dto: EditZoneDto,
    @ExtractToken() accessToken: string,
    @Param("id") id: string,
  ): Promise<EditZoneResponseDto> {
    const result = await this.editZoneUseCase.execute({
      ...dto,
      accessToken,
      id,
    });

    const updatedZone = ZoneResponseMapper.toDto(result.zone);

    return { zone: updatedZone };
  }

  @Delete(":id")
  @ApiOperation({
    summary: "Delete a zone",
    description: "Deletes an existing zone by its ID",
  })
  @Roles(Role.Operator)
  @RequirePermissions(Permission.ZONES_DELETE)
  @HttpCode(HttpStatus.NO_CONTENT)
  @ResponseMessage("Zone deleted")
  @ApiNoContentEnvelope()
  @ApiError401("Access token is missing, invalid, or expired")
  @ApiError403("Insufficient permissions to delete zone")
  @ApiError404("Zone not found")
  @ApiError429("Too many requests")
  @ApiError500("Internal server error while deleting zone")
  async deleteZone(@Param("id") id: string): Promise<void> {
    await this.deleteZoneUseCase.execute(id);
  }
}
