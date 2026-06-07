import { Body, Controller, Get, HttpCode, HttpStatus, Inject, Put } from '@nestjs/common';
import { ApiBody, ApiOperation } from '@nestjs/swagger';
import { GetDecryptionFailurePolicyUseCase } from '../../application/use-cases/get-decryption-failure-policy.use-case.js';
import { UpdateDecryptionFailurePolicyUseCase } from '../../application/use-cases/update-decryption-failure-policy.use-case.js';
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
  DecryptionFailurePolicyDto,
  GetDecryptionFailurePolicyResponseDto,
  UpdateDecryptionFailurePolicyResponseDto,
} from '../dtos/decryption-failure-policy.dto.js';

@Controller('ssl/decryption-failure-policy')
export class DecryptionFailurePolicyController {
  constructor(
    @Inject(GetDecryptionFailurePolicyUseCase)
    private readonly getDecryptionFailurePolicyUseCase: GetDecryptionFailurePolicyUseCase,
    @Inject(UpdateDecryptionFailurePolicyUseCase)
    private readonly updateDecryptionFailurePolicyUseCase: UpdateDecryptionFailurePolicyUseCase,
  ) {}

  @Get()
  @ApiOperation({
    summary: 'Get SSL decryption failure policy',
    description: 'Returns the active SSL decryption failure handling policy.',
  })
  @Roles(Role.Viewer)
  @RequirePermissions(Permission.SNAPSHOTS_READ)
  @HttpCode(HttpStatus.OK)
  @ResponseMessage('SSL decryption failure policy retrieved')
  @ApiOkEnvelope(
    GetDecryptionFailurePolicyResponseDto,
    'SSL decryption failure policy retrieved',
  )
  @ApiError401('Access token is missing, invalid, or expired')
  @ApiError403('Insufficient permissions to read SSL decryption failure policy')
  @ApiError429('Too many requests')
  @ApiError500('Internal server error while retrieving SSL decryption failure policy')
  async getDecryptionFailurePolicy(): Promise<GetDecryptionFailurePolicyResponseDto> {
    return this.getDecryptionFailurePolicyUseCase.execute();
  }

  @Put()
  @ApiOperation({
    summary: 'Update SSL decryption failure policy',
    description: 'Persists SSL decryption failure policy and pushes it to the firewall.',
  })
  @Roles(Role.Operator)
  @RequirePermissions(Permission.SNAPSHOTS_CREATE)
  @HttpCode(HttpStatus.OK)
  @ApiBody({ type: DecryptionFailurePolicyDto })
  @ResponseMessage('SSL decryption failure policy updated')
  @ApiOkEnvelope(
    UpdateDecryptionFailurePolicyResponseDto,
    'SSL decryption failure policy updated',
  )
  @ApiError400('Validation failed')
  @ApiError401('Access token is missing, invalid, or expired')
  @ApiError403('Insufficient permissions to update SSL decryption failure policy')
  @ApiError404('Active configuration snapshot not found')
  @ApiError429('Too many requests')
  @ApiError500('Internal server error while updating SSL decryption failure policy')
  async updateDecryptionFailurePolicy(
    @Body() dto: DecryptionFailurePolicyDto,
    @ExtractToken() accessToken: string,
  ): Promise<UpdateDecryptionFailurePolicyResponseDto> {
    return this.updateDecryptionFailurePolicyUseCase.execute({
      ...dto,
      accessToken,
    });
  }
}
