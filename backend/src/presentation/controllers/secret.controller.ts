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
import { GetSecretMetadataUseCase } from '../../application/use-cases/get-secret-metadata.use-case.js';
import { UpsertSecretUseCase } from '../../application/use-cases/upsert-secret.use-case.js';
import { Permission } from '../../domain/enums/permissions.enum.js';
import { Role } from '../../domain/enums/role.enum.js';
import {
  ApiCreatedEnvelope,
  ApiOkEnvelope,
} from '../decorators/api-envelope-response.decorator.js';
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
import { SecretMetadataResponseDto } from '../dtos/secret-metadata-response.dto.js';
import { UpsertSecretDto } from '../dtos/upsert-secret.dto.js';

@Controller('secrets')
export class SecretController {
  constructor(
    @Inject(UpsertSecretUseCase)
    private readonly upsertSecretUseCase: UpsertSecretUseCase,
    @Inject(GetSecretMetadataUseCase)
    private readonly getSecretMetadataUseCase: GetSecretMetadataUseCase,
  ) {}

  @ApiOperation({
    summary: 'Create or replace a managed secret',
    description:
      'Stores a managed secret value and returns metadata only. The secret value is never returned.',
  })
  @Roles(Role.Admin, Role.SuperAdmin)
  @RequirePermissions(Permission.SNAPSHOTS_CREATE)
  @Put(':scope/:type/:name')
  @HttpCode(HttpStatus.CREATED)
  @ApiBody({ type: UpsertSecretDto })
  @ResponseMessage('Secret stored')
  @ApiCreatedEnvelope(SecretMetadataResponseDto, 'Secret stored')
  @ApiError400('Validation failed')
  @ApiError401('Access token is missing, invalid, or expired')
  @ApiError403('Insufficient permissions to store secrets')
  @ApiError429('Too many requests')
  @ApiError500('Internal server error while storing secret')
  async upsertSecret(
    @Param('scope') scope: string,
    @Param('type') type: string,
    @Param('name') name: string,
    @Body() dto: UpsertSecretDto,
    @ExtractToken() accessToken: string,
  ): Promise<SecretMetadataResponseDto> {
    return this.upsertSecretUseCase.execute({
      scope,
      type,
      name,
      value: dto.value,
      accessToken,
    });
  }

  @ApiOperation({
    summary: 'Get managed secret metadata',
    description:
      'Returns metadata for a managed secret without exposing encrypted or plaintext values.',
  })
  @Roles(Role.Admin, Role.SuperAdmin)
  @RequirePermissions(Permission.SNAPSHOTS_READ)
  @Get(':scope/:type/:name')
  @HttpCode(HttpStatus.OK)
  @ResponseMessage('Secret metadata retrieved')
  @ApiOkEnvelope(SecretMetadataResponseDto, 'Secret metadata retrieved')
  @ApiError400('Validation failed')
  @ApiError401('Access token is missing, invalid, or expired')
  @ApiError403('Insufficient permissions to read secret metadata')
  @ApiError404('Secret not found')
  @ApiError429('Too many requests')
  @ApiError500('Internal server error while reading secret metadata')
  async getSecretMetadata(
    @Param('scope') scope: string,
    @Param('type') type: string,
    @Param('name') name: string,
  ): Promise<SecretMetadataResponseDto> {
    return this.getSecretMetadataUseCase.execute({
      scope,
      type,
      name,
    });
  }
}
