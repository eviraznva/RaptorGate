import {
  Body,
  Controller,
  Delete,
  Get,
  HttpCode,
  HttpStatus,
  Inject,
  Param,
  Patch,
  Post,
  Put,
} from '@nestjs/common';
import { ApiBody, ApiOperation } from '@nestjs/swagger';
import { Throttle } from '@nestjs/throttler';
import { CreateAuthenticationProfileUseCase } from '../../application/use-cases/create-authentication-profile.use-case.js';
import { CreateLdapProfileUseCase } from '../../application/use-cases/create-ldap-profile.use-case.js';
import { CreateRadiusProfileUseCase } from '../../application/use-cases/create-radius-profile.use-case.js';
import { DeleteAuthenticationProfileUseCase } from '../../application/use-cases/delete-authentication-profile.use-case.js';
import { DeleteLdapProfileUseCase } from '../../application/use-cases/delete-ldap-profile.use-case.js';
import { DeleteRadiusProfileUseCase } from '../../application/use-cases/delete-radius-profile.use-case.js';
import { GetIdentityConfigUseCase } from '../../application/use-cases/get-identity-config.use-case.js';
import { TestLdapProfileUseCase } from '../../application/use-cases/test-ldap-profile.use-case.js';
import { TestRadiusProfileUseCase } from '../../application/use-cases/test-radius-profile.use-case.js';
import { UpdateAuthenticationProfileUseCase } from '../../application/use-cases/update-authentication-profile.use-case.js';
import { UpdateIdentitySettingsUseCase } from '../../application/use-cases/update-identity-settings.use-case.js';
import { UpdateLdapProfileUseCase } from '../../application/use-cases/update-ldap-profile.use-case.js';
import { UpdateRadiusProfileUseCase } from '../../application/use-cases/update-radius-profile.use-case.js';
import type { AdminRoleMapping } from '../../domain/entities/identity-authentication-profile.entity.js';
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
  ApiError409,
  ApiError429,
  ApiError500,
} from '../decorators/api-error-response.decorator.js';
import { ExtractToken } from '../decorators/auth/extract-token.decorator.js';
import { RequirePermissions } from '../decorators/auth/require-permissions.decorator.js';
import { Roles } from '../decorators/auth/roles.decorator.js';
import { ResponseMessage } from '../decorators/response-message.decorator.js';
import { IdentityConfigResponseDto } from '../dtos/identity-config-profile-response.dto.js';
import {
  CreateIdentityAuthenticationProfileDto,
  CreateLdapServerProfileDto,
  CreateRadiusServerProfileDto,
  UpdateIdentityAuthenticationProfileDto,
  UpdateIdentitySettingsDto,
  UpdateLdapServerProfileDto,
  UpdateRadiusServerProfileDto,
} from '../dtos/identity-config-profile.dto.js';
import {
  IdentityProviderTestResponseDto,
  TestLdapProfileDto,
  TestRadiusProfileDto,
} from '../dtos/identity-provider-test.dto.js';
import { IdentityConfigResponseMapper } from '../mappers/identity-config-response.mapper.js';

@Controller('identity-config')
export class IdentityConfigController {
  constructor(
    @Inject(GetIdentityConfigUseCase)
    private readonly getIdentityConfigUseCase: GetIdentityConfigUseCase,
    @Inject(CreateRadiusProfileUseCase)
    private readonly createRadiusProfileUseCase: CreateRadiusProfileUseCase,
    @Inject(UpdateRadiusProfileUseCase)
    private readonly updateRadiusProfileUseCase: UpdateRadiusProfileUseCase,
    @Inject(DeleteRadiusProfileUseCase)
    private readonly deleteRadiusProfileUseCase: DeleteRadiusProfileUseCase,
    @Inject(CreateLdapProfileUseCase)
    private readonly createLdapProfileUseCase: CreateLdapProfileUseCase,
    @Inject(UpdateLdapProfileUseCase)
    private readonly updateLdapProfileUseCase: UpdateLdapProfileUseCase,
    @Inject(DeleteLdapProfileUseCase)
    private readonly deleteLdapProfileUseCase: DeleteLdapProfileUseCase,
    @Inject(CreateAuthenticationProfileUseCase)
    private readonly createAuthenticationProfileUseCase: CreateAuthenticationProfileUseCase,
    @Inject(UpdateAuthenticationProfileUseCase)
    private readonly updateAuthenticationProfileUseCase: UpdateAuthenticationProfileUseCase,
    @Inject(DeleteAuthenticationProfileUseCase)
    private readonly deleteAuthenticationProfileUseCase: DeleteAuthenticationProfileUseCase,
    @Inject(UpdateIdentitySettingsUseCase)
    private readonly updateIdentitySettingsUseCase: UpdateIdentitySettingsUseCase,
    @Inject(TestRadiusProfileUseCase)
    private readonly testRadiusProfileUseCase: TestRadiusProfileUseCase,
    @Inject(TestLdapProfileUseCase)
    private readonly testLdapProfileUseCase: TestLdapProfileUseCase,
  ) {}

  @ApiOperation({
    summary: 'Get identity provider configuration',
    description:
      'Returns RADIUS, LDAP, authentication profile and identity settings configuration. Secret values are never returned.',
  })
  @Roles(Role.Viewer)
  @RequirePermissions(Permission.IDENTITY_READ)
  @Get()
  @HttpCode(HttpStatus.OK)
  @ResponseMessage('Identity configuration retrieved')
  @ApiOkEnvelope(IdentityConfigResponseDto, 'Identity configuration retrieved')
  @ApiError401('Access token is missing, invalid, or expired')
  @ApiError403('Insufficient permissions to view identity configuration')
  @ApiError429('Too many requests')
  @ApiError500('Internal server error while reading identity configuration')
  async getIdentityConfig(): Promise<IdentityConfigResponseDto> {
    const config = await this.getIdentityConfigUseCase.execute();
    return IdentityConfigResponseMapper.toResponse(config);
  }

  @ApiOperation({
    summary: 'Create RADIUS server profile',
    description:
      'Creates a RADIUS server profile using an existing managed shared-secret reference.',
  })
  @Roles(Role.Admin, Role.SuperAdmin)
  @RequirePermissions(Permission.IDENTITY_UPDATE)
  @Post('radius-profiles')
  @HttpCode(HttpStatus.CREATED)
  @ApiBody({ type: CreateRadiusServerProfileDto })
  @ResponseMessage('RADIUS server profile created')
  @ApiCreatedEnvelope(IdentityConfigResponseDto, 'RADIUS server profile created')
  @ApiError400('Validation failed')
  @ApiError401('Access token is missing, invalid, or expired')
  @ApiError403('Insufficient permissions to update identity configuration')
  @ApiError409('Identity profile conflict')
  @ApiError429('Too many requests')
  @ApiError500('Internal server error while creating RADIUS server profile')
  async createRadiusProfile(
    @Body() dto: CreateRadiusServerProfileDto,
    @ExtractToken() accessToken: string,
  ): Promise<IdentityConfigResponseDto> {
    const config = await this.createRadiusProfileUseCase.execute({
      ...dto,
      description: dto.description ?? null,
      nasIp: dto.nasIp ?? null,
      nasIdentifier: dto.nasIdentifier ?? null,
      calledStationId: dto.calledStationId ?? null,
      accessToken,
    });
    return IdentityConfigResponseMapper.toResponse(config);
  }

  @ApiOperation({
    summary: 'Update RADIUS server profile',
    description:
      'Replaces a RADIUS server profile while preserving its creation metadata.',
  })
  @Roles(Role.Admin, Role.SuperAdmin)
  @RequirePermissions(Permission.IDENTITY_UPDATE)
  @Put('radius-profiles/:id')
  @HttpCode(HttpStatus.OK)
  @ApiBody({ type: UpdateRadiusServerProfileDto })
  @ResponseMessage('RADIUS server profile updated')
  @ApiOkEnvelope(IdentityConfigResponseDto, 'RADIUS server profile updated')
  @ApiError400('Validation failed')
  @ApiError401('Access token is missing, invalid, or expired')
  @ApiError403('Insufficient permissions to update identity configuration')
  @ApiError404('RADIUS server profile not found')
  @ApiError409('Identity profile conflict')
  @ApiError429('Too many requests')
  @ApiError500('Internal server error while updating RADIUS server profile')
  async updateRadiusProfile(
    @Param('id') id: string,
    @Body() dto: UpdateRadiusServerProfileDto,
    @ExtractToken() accessToken: string,
  ): Promise<IdentityConfigResponseDto> {
    const config = await this.updateRadiusProfileUseCase.execute({
      ...dto,
      id,
      description: dto.description ?? null,
      nasIp: dto.nasIp ?? null,
      nasIdentifier: dto.nasIdentifier ?? null,
      calledStationId: dto.calledStationId ?? null,
      accessToken,
    });
    return IdentityConfigResponseMapper.toResponse(config);
  }

  @ApiOperation({
    summary: 'Delete RADIUS server profile',
    description:
      'Deletes a RADIUS server profile if no authentication profile references it.',
  })
  @Roles(Role.Admin, Role.SuperAdmin)
  @RequirePermissions(Permission.IDENTITY_UPDATE)
  @Delete('radius-profiles/:id')
  @HttpCode(HttpStatus.OK)
  @ResponseMessage('RADIUS server profile deleted')
  @ApiOkEnvelope(IdentityConfigResponseDto, 'RADIUS server profile deleted')
  @ApiError400('Validation failed')
  @ApiError401('Access token is missing, invalid, or expired')
  @ApiError403('Insufficient permissions to update identity configuration')
  @ApiError404('RADIUS server profile not found')
  @ApiError409('RADIUS server profile is in use')
  @ApiError429('Too many requests')
  @ApiError500('Internal server error while deleting RADIUS server profile')
  async deleteRadiusProfile(
    @Param('id') id: string,
    @ExtractToken() accessToken: string,
  ): Promise<IdentityConfigResponseDto> {
    const config = await this.deleteRadiusProfileUseCase.execute({
      id,
      accessToken,
    });
    return IdentityConfigResponseMapper.toResponse(config);
  }

  @ApiOperation({
    summary: 'Test RADIUS server profile',
    description:
      'Sends a RADIUS Access-Request using the selected profile and returns diagnostics without exposing secrets.',
  })
  @Roles(Role.Admin, Role.SuperAdmin)
  @RequirePermissions(Permission.IDENTITY_UPDATE)
  @Post('radius-profiles/:id/test')
  @HttpCode(HttpStatus.OK)
  @Throttle({ default: { limit: 5, ttl: 60_000 } })
  @ApiBody({ type: TestRadiusProfileDto })
  @ResponseMessage('RADIUS server profile tested')
  @ApiOkEnvelope(IdentityProviderTestResponseDto, 'RADIUS server profile tested')
  @ApiError400('Validation failed')
  @ApiError401('Access token is missing, invalid, or expired')
  @ApiError403('Insufficient permissions to update identity configuration')
  @ApiError404('RADIUS server profile not found')
  @ApiError429('Too many profile test requests')
  @ApiError500('Internal server error while testing RADIUS server profile')
  async testRadiusProfile(
    @Param('id') id: string,
    @Body() dto: TestRadiusProfileDto,
    @ExtractToken() accessToken: string,
  ): Promise<IdentityProviderTestResponseDto> {
    return this.testRadiusProfileUseCase.execute({
      id,
      username: dto.username,
      password: dto.password,
      callingStationId: dto.callingStationId ?? '127.0.0.1',
      accessToken,
    });
  }

  @ApiOperation({
    summary: 'Create LDAP server profile',
    description:
      'Creates an LDAP server profile using an existing managed bind-password reference.',
  })
  @Roles(Role.Admin, Role.SuperAdmin)
  @RequirePermissions(Permission.IDENTITY_UPDATE)
  @Post('ldap-profiles')
  @HttpCode(HttpStatus.CREATED)
  @ApiBody({ type: CreateLdapServerProfileDto })
  @ResponseMessage('LDAP server profile created')
  @ApiCreatedEnvelope(IdentityConfigResponseDto, 'LDAP server profile created')
  @ApiError400('Validation failed')
  @ApiError401('Access token is missing, invalid, or expired')
  @ApiError403('Insufficient permissions to update identity configuration')
  @ApiError409('Identity profile conflict')
  @ApiError429('Too many requests')
  @ApiError500('Internal server error while creating LDAP server profile')
  async createLdapProfile(
    @Body() dto: CreateLdapServerProfileDto,
    @ExtractToken() accessToken: string,
  ): Promise<IdentityConfigResponseDto> {
    const config = await this.createLdapProfileUseCase.execute({
      ...dto,
      description: dto.description ?? null,
      accessToken,
    });
    return IdentityConfigResponseMapper.toResponse(config);
  }

  @ApiOperation({
    summary: 'Update LDAP server profile',
    description:
      'Replaces an LDAP server profile while preserving its creation metadata.',
  })
  @Roles(Role.Admin, Role.SuperAdmin)
  @RequirePermissions(Permission.IDENTITY_UPDATE)
  @Put('ldap-profiles/:id')
  @HttpCode(HttpStatus.OK)
  @ApiBody({ type: UpdateLdapServerProfileDto })
  @ResponseMessage('LDAP server profile updated')
  @ApiOkEnvelope(IdentityConfigResponseDto, 'LDAP server profile updated')
  @ApiError400('Validation failed')
  @ApiError401('Access token is missing, invalid, or expired')
  @ApiError403('Insufficient permissions to update identity configuration')
  @ApiError404('LDAP server profile not found')
  @ApiError409('Identity profile conflict')
  @ApiError429('Too many requests')
  @ApiError500('Internal server error while updating LDAP server profile')
  async updateLdapProfile(
    @Param('id') id: string,
    @Body() dto: UpdateLdapServerProfileDto,
    @ExtractToken() accessToken: string,
  ): Promise<IdentityConfigResponseDto> {
    const config = await this.updateLdapProfileUseCase.execute({
      ...dto,
      id,
      description: dto.description ?? null,
      accessToken,
    });
    return IdentityConfigResponseMapper.toResponse(config);
  }

  @ApiOperation({
    summary: 'Delete LDAP server profile',
    description:
      'Deletes an LDAP server profile if no authentication profile references it.',
  })
  @Roles(Role.Admin, Role.SuperAdmin)
  @RequirePermissions(Permission.IDENTITY_UPDATE)
  @Delete('ldap-profiles/:id')
  @HttpCode(HttpStatus.OK)
  @ResponseMessage('LDAP server profile deleted')
  @ApiOkEnvelope(IdentityConfigResponseDto, 'LDAP server profile deleted')
  @ApiError400('Validation failed')
  @ApiError401('Access token is missing, invalid, or expired')
  @ApiError403('Insufficient permissions to update identity configuration')
  @ApiError404('LDAP server profile not found')
  @ApiError409('LDAP server profile is in use')
  @ApiError429('Too many requests')
  @ApiError500('Internal server error while deleting LDAP server profile')
  async deleteLdapProfile(
    @Param('id') id: string,
    @ExtractToken() accessToken: string,
  ): Promise<IdentityConfigResponseDto> {
    const config = await this.deleteLdapProfileUseCase.execute({
      id,
      accessToken,
    });
    return IdentityConfigResponseMapper.toResponse(config);
  }

  @ApiOperation({
    summary: 'Test LDAP server profile',
    description:
      'Binds to LDAP using the selected profile and performs a user/group lookup for diagnostics.',
  })
  @Roles(Role.Admin, Role.SuperAdmin)
  @RequirePermissions(Permission.IDENTITY_UPDATE)
  @Post('ldap-profiles/:id/test')
  @HttpCode(HttpStatus.OK)
  @Throttle({ default: { limit: 5, ttl: 60_000 } })
  @ApiBody({ type: TestLdapProfileDto })
  @ResponseMessage('LDAP server profile tested')
  @ApiOkEnvelope(IdentityProviderTestResponseDto, 'LDAP server profile tested')
  @ApiError400('Validation failed')
  @ApiError401('Access token is missing, invalid, or expired')
  @ApiError403('Insufficient permissions to update identity configuration')
  @ApiError404('LDAP server profile not found')
  @ApiError429('Too many profile test requests')
  @ApiError500('Internal server error while testing LDAP server profile')
  async testLdapProfile(
    @Param('id') id: string,
    @Body() dto: TestLdapProfileDto,
    @ExtractToken() accessToken: string,
  ): Promise<IdentityProviderTestResponseDto> {
    return this.testLdapProfileUseCase.execute({
      id,
      username: dto.username,
      accessToken,
    });
  }

  @ApiOperation({
    summary: 'Create identity authentication profile',
    description:
      'Creates an authentication profile that binds identity login to configured RADIUS, LDAP or local providers.',
  })
  @Roles(Role.Admin, Role.SuperAdmin)
  @RequirePermissions(Permission.IDENTITY_UPDATE)
  @Post('authentication-profiles')
  @HttpCode(HttpStatus.CREATED)
  @ApiBody({ type: CreateIdentityAuthenticationProfileDto })
  @ResponseMessage('Identity authentication profile created')
  @ApiCreatedEnvelope(
    IdentityConfigResponseDto,
    'Identity authentication profile created',
  )
  @ApiError400('Validation failed')
  @ApiError401('Access token is missing, invalid, or expired')
  @ApiError403('Insufficient permissions to update identity configuration')
  @ApiError404('Referenced identity provider profile not found')
  @ApiError409('Identity profile conflict')
  @ApiError429('Too many requests')
  @ApiError500('Internal server error while creating authentication profile')
  async createAuthenticationProfile(
    @Body() dto: CreateIdentityAuthenticationProfileDto,
    @ExtractToken() accessToken: string,
  ): Promise<IdentityConfigResponseDto> {
    const config = await this.createAuthenticationProfileUseCase.execute({
      ...dto,
      description: dto.description ?? null,
      radiusProfileId: dto.radiusProfileId ?? null,
      ldapProfileId: dto.ldapProfileId ?? null,
      adminRoleMappings: dto.adminRoleMappings as AdminRoleMapping[] | undefined,
      accessToken,
    });
    return IdentityConfigResponseMapper.toResponse(config);
  }

  @ApiOperation({
    summary: 'Update identity authentication profile',
    description:
      'Replaces an authentication profile while preserving its creation metadata.',
  })
  @Roles(Role.Admin, Role.SuperAdmin)
  @RequirePermissions(Permission.IDENTITY_UPDATE)
  @Put('authentication-profiles/:id')
  @HttpCode(HttpStatus.OK)
  @ApiBody({ type: UpdateIdentityAuthenticationProfileDto })
  @ResponseMessage('Identity authentication profile updated')
  @ApiOkEnvelope(
    IdentityConfigResponseDto,
    'Identity authentication profile updated',
  )
  @ApiError400('Validation failed')
  @ApiError401('Access token is missing, invalid, or expired')
  @ApiError403('Insufficient permissions to update identity configuration')
  @ApiError404('Authentication profile not found')
  @ApiError409('Identity profile conflict')
  @ApiError429('Too many requests')
  @ApiError500('Internal server error while updating authentication profile')
  async updateAuthenticationProfile(
    @Param('id') id: string,
    @Body() dto: UpdateIdentityAuthenticationProfileDto,
    @ExtractToken() accessToken: string,
  ): Promise<IdentityConfigResponseDto> {
    const config = await this.updateAuthenticationProfileUseCase.execute({
      ...dto,
      id,
      description: dto.description ?? null,
      radiusProfileId: dto.radiusProfileId ?? null,
      ldapProfileId: dto.ldapProfileId ?? null,
      adminRoleMappings: dto.adminRoleMappings as AdminRoleMapping[] | undefined,
      accessToken,
    });
    return IdentityConfigResponseMapper.toResponse(config);
  }

  @ApiOperation({
    summary: 'Delete identity authentication profile',
    description:
      'Deletes an authentication profile if identity settings do not reference it.',
  })
  @Roles(Role.Admin, Role.SuperAdmin)
  @RequirePermissions(Permission.IDENTITY_UPDATE)
  @Delete('authentication-profiles/:id')
  @HttpCode(HttpStatus.OK)
  @ResponseMessage('Identity authentication profile deleted')
  @ApiOkEnvelope(
    IdentityConfigResponseDto,
    'Identity authentication profile deleted',
  )
  @ApiError400('Validation failed')
  @ApiError401('Access token is missing, invalid, or expired')
  @ApiError403('Insufficient permissions to update identity configuration')
  @ApiError404('Authentication profile not found')
  @ApiError409('Authentication profile is in use')
  @ApiError429('Too many requests')
  @ApiError500('Internal server error while deleting authentication profile')
  async deleteAuthenticationProfile(
    @Param('id') id: string,
    @ExtractToken() accessToken: string,
  ): Promise<IdentityConfigResponseDto> {
    const config = await this.deleteAuthenticationProfileUseCase.execute({
      id,
      accessToken,
    });
    return IdentityConfigResponseMapper.toResponse(config);
  }

  @ApiOperation({
    summary: 'Update identity settings',
    description:
      'Updates active authentication profile bindings for captive portal and admin login.',
  })
  @Roles(Role.Admin, Role.SuperAdmin)
  @RequirePermissions(Permission.IDENTITY_UPDATE)
  @Patch('settings')
  @HttpCode(HttpStatus.OK)
  @ApiBody({ type: UpdateIdentitySettingsDto })
  @ResponseMessage('Identity settings updated')
  @ApiOkEnvelope(IdentityConfigResponseDto, 'Identity settings updated')
  @ApiError400('Validation failed')
  @ApiError401('Access token is missing, invalid, or expired')
  @ApiError403('Insufficient permissions to update identity configuration')
  @ApiError404('Authentication profile not found')
  @ApiError409('Identity profile conflict')
  @ApiError429('Too many requests')
  @ApiError500('Internal server error while updating identity settings')
  async updateSettings(
    @Body() dto: UpdateIdentitySettingsDto,
    @ExtractToken() accessToken: string,
  ): Promise<IdentityConfigResponseDto> {
    const config = await this.updateIdentitySettingsUseCase.execute({
      portalAuthenticationProfileId: dto.portalAuthenticationProfileId,
      adminAuthenticationProfileId: dto.adminAuthenticationProfileId,
      portalListener: dto.portalListener,
      accessToken,
    });
    return IdentityConfigResponseMapper.toResponse(config);
  }
}
