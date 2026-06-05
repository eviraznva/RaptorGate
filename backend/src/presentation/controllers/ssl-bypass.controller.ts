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
} from '@nestjs/common';
import { ApiBody, ApiOperation } from '@nestjs/swagger';
import { CreateSslBypassDomainUseCase } from '../../application/use-cases/create-ssl-bypass-domain.use-case.js';
import { DeleteSslBypassDomainUseCase } from '../../application/use-cases/delete-ssl-bypass-domain.use-case.js';
import { GetSslBypassDomainsUseCase } from '../../application/use-cases/get-ssl-bypass-domains.use-case.js';
import { Permission } from '../../domain/enums/permissions.enum.js';
import { Role } from '../../domain/enums/role.enum.js';
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
  ApiError429,
  ApiError500,
} from '../decorators/api-error-response.decorator.js';
import { ExtractToken } from '../decorators/auth/extract-token.decorator.js';
import { RequirePermissions } from '../decorators/auth/require-permissions.decorator.js';
import { Roles } from '../decorators/auth/roles.decorator.js';
import { ResponseMessage } from '../decorators/response-message.decorator.js';
import {
  CreateSslBypassDomainDto,
  CreateSslBypassDomainResponseDto,
  GetSslBypassDomainsResponseDto,
} from '../dtos/ssl-bypass-domain.dto.js';

@Controller('ssl/bypass-domains')
export class SslBypassController {
  constructor(
    @Inject(GetSslBypassDomainsUseCase)
    private readonly getSslBypassDomainsUseCase: GetSslBypassDomainsUseCase,
    @Inject(CreateSslBypassDomainUseCase)
    private readonly createSslBypassDomainUseCase: CreateSslBypassDomainUseCase,
    @Inject(DeleteSslBypassDomainUseCase)
    private readonly deleteSslBypassDomainUseCase: DeleteSslBypassDomainUseCase,
  ) {}

  @Get()
  @ApiOperation({
    summary: 'Get TLS inspection bypass domains',
    description: 'Returns configured domains excluded from TLS inspection.',
  })
  @Roles(Role.Viewer)
  @RequirePermissions(Permission.SSL_BYPASS_READ)
  @HttpCode(HttpStatus.OK)
  @ResponseMessage('TLS inspection bypass domains retrieved')
  @ApiOkEnvelope(
    GetSslBypassDomainsResponseDto,
    'TLS inspection bypass domains retrieved',
  )
  @ApiError401('Access token is missing, invalid, or expired')
  @ApiError403('Insufficient permissions to read TLS bypass domains')
  @ApiError429('Too many requests')
  @ApiError500('Internal server error while retrieving TLS bypass domains')
  async getSslBypassDomains(): Promise<GetSslBypassDomainsResponseDto> {
    return this.getSslBypassDomainsUseCase.execute();
  }

  @Post()
  @ApiOperation({
    summary: 'Create TLS inspection bypass domain',
    description:
      'Adds a domain to the TLS inspection bypass list and pushes active config to the firewall.',
  })
  @Roles(Role.Operator)
  @RequirePermissions(Permission.SSL_BYPASS_CREATE)
  @HttpCode(HttpStatus.CREATED)
  @ApiBody({ type: CreateSslBypassDomainDto })
  @ResponseMessage('TLS inspection bypass domain created')
  @ApiCreatedEnvelope(
    CreateSslBypassDomainResponseDto,
    'TLS inspection bypass domain created',
  )
  @ApiError400('Validation failed')
  @ApiError401('Access token is missing, invalid, or expired')
  @ApiError403('Insufficient permissions to create TLS bypass domains')
  @ApiError404('Active configuration snapshot not found')
  @ApiError429('Too many requests')
  @ApiError500('Internal server error while creating TLS bypass domain')
  async createSslBypassDomain(
    @Body() dto: CreateSslBypassDomainDto,
    @ExtractToken() accessToken: string,
  ): Promise<CreateSslBypassDomainResponseDto> {
    return this.createSslBypassDomainUseCase.execute({
      ...dto,
      accessToken,
    });
  }

  @Delete(':id')
  @ApiOperation({
    summary: 'Delete TLS inspection bypass domain',
    description:
      'Removes a domain from the TLS inspection bypass list and pushes active config to the firewall.',
  })
  @Roles(Role.Operator)
  @RequirePermissions(Permission.SSL_BYPASS_DELETE)
  @HttpCode(HttpStatus.NO_CONTENT)
  @ResponseMessage('TLS inspection bypass domain deleted')
  @ApiNoContentEnvelope()
  @ApiError401('Access token is missing, invalid, or expired')
  @ApiError403('Insufficient permissions to delete TLS bypass domains')
  @ApiError404('TLS bypass domain not found')
  @ApiError429('Too many requests')
  @ApiError500('Internal server error while deleting TLS bypass domain')
  async deleteSslBypassDomain(
    @Param('id') id: string,
    @ExtractToken() accessToken: string,
  ): Promise<void> {
    await this.deleteSslBypassDomainUseCase.execute({
      id,
      accessToken,
    });
  }
}
