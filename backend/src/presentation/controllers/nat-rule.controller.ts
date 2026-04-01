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
  ApiError429,
  ApiError500,
} from '../decorators/api-error-response.decorator.js';
import { RequirePermissions } from '../decorators/auth/require-permissions.decorator.js';
import { GetAllNatRulesUseCase } from '../../application/use-cases/get-all-nat-rules.use-case.js';
import { CreateNatRuleUseCase } from '../../application/use-cases/create-nat-rule.use-case.js';
import { DeleteNatRuleUseCase } from '../../application/use-cases/delete-nat-rule.use-case.js';
import { EditNatRuleUseCase } from '../../application/use-cases/edit-nat-rule.use-case.js';
import { ExtractToken } from '../decorators/auth/extract-token.decorator.js';
import { GetAllNatRulesResponseDto } from '../dtos/get-all-nat-rules-response.dto.js';
import { CreateNatRuleResponseDto } from '../dtos/create-nat-rule-response.dto.js';
import { EditNatRuleResponseDto } from '../dtos/edit-nat-rule-response.dto.js';
import { NatRuleResponseMapper } from '../mappers/nat-rule-response.mapper.js';
import { ResponseMessage } from '../decorators/response-message.decorator.js';
import { Roles } from '../decorators/auth/roles.decorator.js';
import { Permission } from '../../domain/enums/permissions.enum.js';
import { CreateNatRuleDto } from '../dtos/create-nat-rule.dto.js';
import { EditNatRuleDto } from '../dtos/edit-nat-rule.dto.js';
import { ApiBody, ApiOperation } from '@nestjs/swagger';
import { Role } from '../../domain/enums/role.enum.js';

@Controller('nat')
export class NatRuleController {
  constructor(
    @Inject(CreateNatRuleUseCase)
    private readonly createNatRuleUseCase: CreateNatRuleUseCase,
    @Inject(GetAllNatRulesUseCase)
    private readonly getAllNatRulesUseCase: GetAllNatRulesUseCase,
    @Inject(EditNatRuleUseCase)
    private readonly editNatRuleUseCase: EditNatRuleUseCase,
    @Inject(DeleteNatRuleUseCase)
    private readonly deleteNatRuleUseCase: DeleteNatRuleUseCase,
  ) {}

  @ApiOperation({
    summary: 'Create a new NAT rule',
    description:
      'Creates a new NAT rule with the specified parameters. Requires Operator role and NAT_RULES_CREATE permission.',
  })
  @Post()
  @Roles(Role.Operator)
  @RequirePermissions(Permission.NAT_RULES_CREATE)
  @HttpCode(HttpStatus.CREATED)
  @ApiBody({ type: CreateNatRuleDto })
  @ResponseMessage('NAT rule created')
  @ApiCreatedEnvelope(CreateNatRuleResponseDto, 'NAT rule created')
  @ApiError400('Validation failed')
  @ApiError401('Authorization header missing or invalid')
  @ApiError403('Insufficient permissions')
  @ApiError429('Too many requests')
  @ApiError500('Server error while creating NAT rule')
  async createNatRule(
    @Body() createNatRuleDto: CreateNatRuleDto,
    @ExtractToken() accessToken: string,
  ): Promise<CreateNatRuleResponseDto> {
    const result = await this.createNatRuleUseCase.execute({
      ...createNatRuleDto,
      accessToken,
    });

    const natRule = NatRuleResponseMapper.toDto(result.natRule);

    return { natRule };
  }

  @ApiOperation({
    summary: 'Get all NAT rules',
    description:
      'Gets a list of all NAT rules. Requires Viewer role and NAT_RULES_READ permission.',
  })
  @Get()
  @Roles(Role.Viewer)
  @RequirePermissions(Permission.NAT_RULES_READ)
  @HttpCode(HttpStatus.OK)
  @ResponseMessage('List of NAT rules retrieved')
  @ApiOkEnvelope(GetAllNatRulesResponseDto, 'List of NAT rules retrieved')
  @ApiError401('Access token is missing, invalid, or expired')
  @ApiError403('Insufficient permissions to view NAT rules')
  @ApiError404('NAT rules not found')
  @ApiError429('Too many requests')
  @ApiError500('Internal server error while retrieving NAT rules')
  async getAllNatRules(): Promise<GetAllNatRulesResponseDto> {
    const result = await this.getAllNatRulesUseCase.execute();
    const natRules = result.natRules.map((natRule) =>
      NatRuleResponseMapper.toDto(natRule),
    );

    return { natRules };
  }

  @ApiOperation({
    summary: 'Edit an existing NAT rule',
    description:
      'Edits an existing NAT rule with the specified parameters. Requires Operator role and NAT_RULES_EDIT permission.',
  })
  @Put(':id')
  @Roles(Role.Operator)
  @RequirePermissions(Permission.NAT_RULES_UPDATE)
  @HttpCode(HttpStatus.OK)
  @ApiBody({ type: EditNatRuleDto })
  @ResponseMessage('NAT rule updated')
  @ApiOkEnvelope(EditNatRuleResponseDto, 'NAT rule updated')
  @ApiError400('Validation failed')
  @ApiError401('Access token is missing, invalid, or expired')
  @ApiError403('Insufficient permissions to edit NAT rule')
  @ApiError404('NAT rule not found')
  @ApiError429('Too many requests')
  @ApiError500('Internal server error while editing NAT rule')
  async editNatRule(
    @Body() dto: EditNatRuleDto,
    @Param('id') id: string,
  ): Promise<EditNatRuleResponseDto> {
    const result = await this.editNatRuleUseCase.execute({
      id,
      ...dto,
    });

    const natRule = NatRuleResponseMapper.toDto(result.natRule);

    return { natRule };
  }

  @ApiOperation({
    summary: 'Delete a NAT rule',
    description:
      'Deletes a NAT rule by its ID. Requires Operator role and NAT_RULES_DELETE permission.',
  })
  @Delete(':id')
  @Roles(Role.Operator)
  @RequirePermissions(Permission.NAT_RULES_DELETE)
  @HttpCode(HttpStatus.NO_CONTENT)
  @ResponseMessage('NAT rule deleted')
  @ApiNoContentEnvelope()
  @ApiError401('Access token is missing, invalid, or expired')
  @ApiError403('Insufficient permissions to delete NAT rule')
  @ApiError404('NAT rule not found')
  @ApiError429('Too many requests')
  @ApiError500('Internal server error while deleting NAT rule')
  async deleteNatRule(@Param('id') id: string): Promise<void> {
    await this.deleteNatRuleUseCase.execute(id);
  }
}
