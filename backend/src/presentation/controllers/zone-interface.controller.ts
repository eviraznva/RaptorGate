import {
  Body,
  Controller,
  Get,
  HttpCode,
  HttpStatus,
  Inject,
  Param,
  Put,
} from '@nestjs/common';
import { ApiBody, ApiOperation } from '@nestjs/swagger';
import { EditZoneInterfaceUseCase } from '../../application/use-cases/edit-zone-interface.use-case.js';
import { GetLiveZoneInterfacesUseCase } from '../../application/use-cases/get-live-zone-interfaces.use-case.js';
import { Permission } from '../../domain/enums/permissions.enum.js';
import { Role } from '../../domain/enums/role.enum.js';
import { ApiOkEnvelope } from '../decorators/api-envelope-response.decorator.js';
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
import { EditZoneInterfaceDto } from '../dtos/edit-zone-interface.dto.js';
import { EditZoneInterfaceResponseDto } from '../dtos/edit-zone-interface-response.dto.js';
import { GetLiveZoneInterfacesResponseDto } from '../dtos/get-live-zone-interfaces-response.dto.js';
import { ZoneInterfaceResponseMapper } from '../mappers/zone-interface-response.mapper.js';

@Controller('zone-interface')
export class ZoneInterfaceController {
  constructor(
    @Inject(GetLiveZoneInterfacesUseCase)
    private readonly getLiveZoneInterfacesUseCase: GetLiveZoneInterfacesUseCase,
    @Inject(EditZoneInterfaceUseCase)
    private readonly editZoneInterfaceUseCase: EditZoneInterfaceUseCase,
  ) {}

  @Get()
  @ApiOperation({
    summary: 'Get live zone interfaces',
    description: 'Gets live zone interfaces from firewall gRPC query service',
  })
  @Roles(Role.Viewer)
  @RequirePermissions(Permission.ZONES_READ)
  @HttpCode(HttpStatus.OK)
  @ResponseMessage('Live zone interfaces retrieved')
  @ApiOkEnvelope(
    GetLiveZoneInterfacesResponseDto,
    'Live zone interfaces retrieved',
  )
  @ApiError401('Access token is missing, invalid, or expired')
  @ApiError403('Insufficient permissions to view zone interfaces')
  @ApiError429('Too many requests')
  @ApiError500('Internal server error while retrieving zone interfaces')
  async getLiveZoneInterfaces(): Promise<GetLiveZoneInterfacesResponseDto> {
    const result = await this.getLiveZoneInterfacesUseCase.execute();

    const zoneInterfaces = result.zoneInterfaces.map((zoneInterface) =>
      ZoneInterfaceResponseMapper.toDto(zoneInterface),
    );

    return { zoneInterfaces };
  }

  @Put(':id')
  @ApiOperation({
    summary: 'Edit zone interface configuration',
    description:
      'Updates zone interface configuration and forwards supported properties to firewall gRPC service',
  })
  @Roles(Role.Admin, Role.SuperAdmin)
  @RequirePermissions(Permission.ZONES_INTERFACES_MANAGE)
  @HttpCode(HttpStatus.OK)
  @ApiBody({ type: EditZoneInterfaceDto })
  @ResponseMessage('Zone interface updated')
  @ApiOkEnvelope(EditZoneInterfaceResponseDto, 'Zone interface updated')
  @ApiError400('Validation failed')
  @ApiError401('Access token is missing, invalid, or expired')
  @ApiError403('Insufficient permissions to edit zone interfaces')
  @ApiError429('Too many requests')
  @ApiError500('Internal server error while editing zone interface')
  async editZoneInterface(
    @Body() dto: EditZoneInterfaceDto,
    @ExtractToken() accessToken: string,
    @Param('id') id: string,
  ): Promise<EditZoneInterfaceResponseDto> {
    const result = await this.editZoneInterfaceUseCase.execute({
      ...dto,
      accessToken,
      id,
    });

    const zoneInterface = ZoneInterfaceResponseMapper.toDto(
      result.zoneInterface,
    );

    return { zoneInterface };
  }
}
