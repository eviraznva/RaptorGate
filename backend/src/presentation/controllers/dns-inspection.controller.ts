import {
  Body,
  Controller,
  Get,
  HttpCode,
  HttpStatus,
  Inject,
  Put,
} from "@nestjs/common";
import { ApiBody, ApiOperation } from "@nestjs/swagger";
import { GetDnsInspectionConfigUseCase } from "../../application/use-cases/get-dns-inspection-config.use-case.js";
import { UpdateDnsInspectionConfigUseCase } from "../../application/use-cases/update-dns-inspection-config.use-case.js";
import { Permission } from "../../domain/enums/permissions.enum.js";
import { Role } from "../../domain/enums/role.enum.js";
import { ApiOkEnvelope } from "../decorators/api-envelope-response.decorator.js";
import {
  ApiError400,
  ApiError401,
  ApiError403,
  ApiError429,
  ApiError500,
} from "../decorators/api-error-response.decorator.js";
import { RequirePermissions } from "../decorators/auth/require-permissions.decorator.js";
import { Roles } from "../decorators/auth/roles.decorator.js";
import { ResponseMessage } from "../decorators/response-message.decorator.js";
import { GetDnsInspectionConfigResponseDto } from "../dtos/get-dns-inspection-config-response.dto.js";
import { UpdateDnsInspectionConfigDto } from "../dtos/update-dns-inspection-config.dto.js";
import { UpdateDnsInspectionConfigResponseDto } from "../dtos/update-dns-inspection-config-response.dto.js";
import { DnsInspectionResponseMapper } from "../mappers/dns-inspection-response.mapper.js";

@Controller("dns-inspection")
export class DnsInspectionController {
  constructor(
    @Inject(GetDnsInspectionConfigUseCase)
    private readonly getDnsInspectionConfigUseCase: GetDnsInspectionConfigUseCase,
    @Inject(UpdateDnsInspectionConfigUseCase)
    private readonly updateDnsInspectionConfigUseCase: UpdateDnsInspectionConfigUseCase,
  ) {}

  @Get()
  @ApiOperation({
    summary: "Get DNS inspection config",
    description: "Returns the persisted DNS inspection configuration.",
  })
  @Roles(Role.Viewer)
  @RequirePermissions(Permission.DNS_INSPECTION_READ)
  @HttpCode(HttpStatus.OK)
  @ResponseMessage("DNS inspection config retrieved")
  @ApiOkEnvelope(
    GetDnsInspectionConfigResponseDto,
    "DNS inspection config retrieved",
  )
  @ApiError401("Access token is missing, invalid, or expired")
  @ApiError403("Insufficient permissions to read DNS inspection config")
  @ApiError429("Too many requests")
  @ApiError500("Internal server error while retrieving DNS inspection config")
  async getDnsInspectionConfig(): Promise<GetDnsInspectionConfigResponseDto> {
    const result = await this.getDnsInspectionConfigUseCase.execute();

    return {
      dnsInspection: DnsInspectionResponseMapper.toDto(result.dnsInspection),
    };
  }

  @Put()
  @ApiOperation({
    summary: "Update DNS inspection config",
    description: "Persists the DNS inspection configuration.",
  })
  @Roles(Role.Operator)
  @RequirePermissions(Permission.DNS_INSPECTION_UPDATE)
  @HttpCode(HttpStatus.OK)
  @ApiBody({ type: UpdateDnsInspectionConfigDto })
  @ResponseMessage("DNS inspection config updated")
  @ApiOkEnvelope(
    UpdateDnsInspectionConfigResponseDto,
    "DNS inspection config updated",
  )
  @ApiError400("Validation failed")
  @ApiError401("Access token is missing, invalid, or expired")
  @ApiError403("Insufficient permissions to update DNS inspection config")
  @ApiError429("Too many requests")
  @ApiError500("Internal server error while updating DNS inspection config")
  async updateDnsInspectionConfig(
    @Body() dto: UpdateDnsInspectionConfigDto,
  ): Promise<UpdateDnsInspectionConfigResponseDto> {
    const result = await this.updateDnsInspectionConfigUseCase.execute(dto);

    return {
      dnsInspection: DnsInspectionResponseMapper.toDto(result.dnsInspection),
    };
  }
}
