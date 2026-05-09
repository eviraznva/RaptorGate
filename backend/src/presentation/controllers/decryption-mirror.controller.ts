import { Body, Controller, Get, HttpCode, HttpStatus, Inject, Put } from '@nestjs/common';
import { ApiBody, ApiOperation } from '@nestjs/swagger';
import { GetDecryptionMirrorConfigUseCase } from '../../application/use-cases/get-decryption-mirror-config.use-case.js';
import { UpdateDecryptionMirrorConfigUseCase } from '../../application/use-cases/update-decryption-mirror-config.use-case.js';
import { Permission } from '../../domain/enums/permissions.enum.js';
import { Role } from '../../domain/enums/role.enum.js';
import { ApiOkEnvelope } from '../decorators/api-envelope-response.decorator.js';
import {
  ApiError400,
  ApiError401,
  ApiError403,
  ApiError404,
  ApiError429,
  ApiError500,
} from '../decorators/api-error-response.decorator.js';
import { ExtractToken } from '../decorators/auth/extract-token.decorator.js';
import { RequirePermissions } from '../decorators/auth/require-permissions.decorator.js';
import { Roles } from '../decorators/auth/roles.decorator.js';
import { ResponseMessage } from '../decorators/response-message.decorator.js';
import {
  DecryptionMirrorConfigDto,
  GetDecryptionMirrorConfigResponseDto,
  UpdateDecryptionMirrorConfigResponseDto,
} from '../dtos/decryption-mirror-config.dto.js';

@Controller('ssl/decryption-mirror')
export class DecryptionMirrorController {
  constructor(
    @Inject(GetDecryptionMirrorConfigUseCase)
    private readonly getDecryptionMirrorConfigUseCase: GetDecryptionMirrorConfigUseCase,
    @Inject(UpdateDecryptionMirrorConfigUseCase)
    private readonly updateDecryptionMirrorConfigUseCase: UpdateDecryptionMirrorConfigUseCase,
  ) {}

  @Get()
  @ApiOperation({
    summary: 'Get SSL decryption mirror config',
    description: 'Returns the active SSL decryption mirror export configuration.',
  })
  @Roles(Role.Viewer)
  @RequirePermissions(Permission.SNAPSHOTS_READ)
  @HttpCode(HttpStatus.OK)
  @ResponseMessage('SSL decryption mirror config retrieved')
  @ApiOkEnvelope(
    GetDecryptionMirrorConfigResponseDto,
    'SSL decryption mirror config retrieved',
  )
  @ApiError401('Access token is missing, invalid, or expired')
  @ApiError403('Insufficient permissions to read SSL decryption mirror config')
  @ApiError429('Too many requests')
  @ApiError500('Internal server error while retrieving SSL decryption mirror config')
  async getDecryptionMirrorConfig(): Promise<GetDecryptionMirrorConfigResponseDto> {
    return this.getDecryptionMirrorConfigUseCase.execute();
  }

  @Put()
  @ApiOperation({
    summary: 'Update SSL decryption mirror config',
    description: 'Persists SSL decryption mirror configuration and pushes it to the firewall.',
  })
  @Roles(Role.Operator)
  @RequirePermissions(Permission.SNAPSHOTS_CREATE)
  @HttpCode(HttpStatus.OK)
  @ApiBody({ type: DecryptionMirrorConfigDto })
  @ResponseMessage('SSL decryption mirror config updated')
  @ApiOkEnvelope(
    UpdateDecryptionMirrorConfigResponseDto,
    'SSL decryption mirror config updated',
  )
  @ApiError400('Validation failed')
  @ApiError401('Access token is missing, invalid, or expired')
  @ApiError403('Insufficient permissions to update SSL decryption mirror config')
  @ApiError404('Active configuration snapshot not found')
  @ApiError429('Too many requests')
  @ApiError500('Internal server error while updating SSL decryption mirror config')
  async updateDecryptionMirrorConfig(
    @Body() dto: DecryptionMirrorConfigDto,
    @ExtractToken() accessToken: string,
  ): Promise<UpdateDecryptionMirrorConfigResponseDto> {
    return this.updateDecryptionMirrorConfigUseCase.execute({
      ...dto,
      accessToken,
    });
  }
}
