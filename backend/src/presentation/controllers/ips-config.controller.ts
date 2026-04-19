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
import { GetIpsConfigurationUseCase } from "src/application/use-cases/get-ips-configuration.use-case";
import { UpdateIpsConfigUseCase } from "src/application/use-cases/update-ips-config.use-case";
import { Permission } from "src/domain/enums/permissions.enum";
import { Role } from "src/domain/enums/role.enum";
import { en } from "zod/locales";
import { ApiOkEnvelope } from "../decorators/api-envelope-response.decorator";
import {
  ApiError400,
  ApiError401,
  ApiError403,
  ApiError429,
  ApiError500,
} from "../decorators/api-error-response.decorator";
import { RequirePermissions } from "../decorators/auth/require-permissions.decorator";
import { Roles } from "../decorators/auth/roles.decorator";
import { ResponseMessage } from "../decorators/response-message.decorator";
import { GetIpsConfigResponseDto } from "../dtos/get-ips-config-response.dto";
import { UpdateIpsConfigDto } from "../dtos/update-ips-config.dto";
import { UpdateIpsConfigResponseDto } from "../dtos/update-ips-config-response.dto";
import {
  IpsConfigResponseMapper,
  mapActionFromDtoValue,
  mapProtocolFromDtoValue,
  mapSeverityFromDtoValue,
} from "../mappers/ips-config-response.mapper";

@Controller("ips-config")
export class IpsConfigController {
  constructor(
    @Inject(GetIpsConfigurationUseCase)
    private readonly getIpsConfigurationUseCase: GetIpsConfigurationUseCase,
    @Inject(UpdateIpsConfigUseCase)
    private readonly updateIpsConfigUseCase: UpdateIpsConfigUseCase,
  ) {}

  @Get()
  @ApiOperation({
    summary: "Get IPS config",
    description: "Returns the persisted IPS configuration.",
  })
  @Roles(Role.Operator)
  @RequirePermissions(Permission.IPS_SIGNATURES_READ)
  @HttpCode(HttpStatus.OK)
  @ResponseMessage("IPS cnofig retrieved")
  @ApiOkEnvelope(GetIpsConfigResponseDto)
  @ApiError401("Access token is missing, invalid, or expired")
  @ApiError403("Insufficient permissions to read IPS config")
  @ApiError429("Too many requests")
  @ApiError500("Internal server error while retrieving IPS config")
  async getIpsConfig(): Promise<GetIpsConfigResponseDto> {
    const result = await this.getIpsConfigurationUseCase.execute();

    const ipsConfig = IpsConfigResponseMapper.toDto(result.ipsConfig);

    return { ipsConfig };
  }

  @Put()
  @ApiOperation({
    summary: "Update IPS config",
    description: "Persists the IPS configuration",
  })
  @Roles(Role.Operator)
  @RequirePermissions(Permission.IPS_SIGNATURES_UPDATE)
  @HttpCode(HttpStatus.OK)
  @ApiBody({ type: UpdateIpsConfigDto })
  @ResponseMessage("Ips config updated")
  @ApiOkEnvelope(UpdateIpsConfigDto)
  @ApiError400("Validation failed")
  @ApiError401("Access token is missing, invalid, or expired")
  @ApiError403("Insufficient permissions to update IPS config")
  @ApiError429("Too many requests")
  @ApiError500("Internal server error while updating IPS config")
  async updateUpsConfig(
    @Body() dto: UpdateIpsConfigDto,
  ): Promise<UpdateIpsConfigResponseDto> {
    const result = await this.updateIpsConfigUseCase.execute({
      general: dto.general,
      detection: dto.detection,
      signatures: dto.signatures.map((signature) => {
        return {
          ...signature,
          severity: mapSeverityFromDtoValue(signature.severity),
          action: mapActionFromDtoValue(signature.action),
          appProtocols: signature.appProtocols.map((appProtocol) =>
            mapProtocolFromDtoValue(appProtocol),
          ),
        };
      }),
    });

    const ipsConfig = IpsConfigResponseMapper.toDto(result.ipsConfig);

    return { ipsConfig };
  }
}
