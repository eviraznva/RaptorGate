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
} from '@nestjs/common';
import { ApiBody, ApiOperation } from '@nestjs/swagger';
import { CreateRuleUseCase } from '../../application/use-cases/create-rule.use-case.js';
import { DeleteRuleUseCase } from '../../application/use-cases/delete-rule.use-case.js';
import { EditRuleUseCase } from '../../application/use-cases/edit-rule.use-case.js';
import { GetAllRulesUseCase } from '../../application/use-cases/get-all-rules.use-case.js';
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
  ApiError409,
  ApiError429,
  ApiError500,
} from '../decorators/api-error-response.decorator.js';
import { ExtractToken } from '../decorators/auth/extract-token.decorator.js';
import { RequirePermissions } from '../decorators/auth/require-permissions.decorator.js';
import { Roles } from '../decorators/auth/roles.decorator.js';
import { ResponseMessage } from '../decorators/response-message.decorator.js';
import { CreateRuleDto } from '../dtos/create-rule.dto.js';
import { CreateRuleResponseDto } from '../dtos/create-rule-response.dto.js';
import { EditRuleDto } from '../dtos/edit-rule.dto.js';
import { EditRuleResponseDto } from '../dtos/edit-rule-response.dto.js';
import { GetAllRulesResponseDto } from '../dtos/get-all-rules-response.dto.js';
import { GetRulesQueryDto } from '../dtos/get-rules-query.dto.js';
import { RuleResponseMapper } from '../mappers/rule-response.mapper.js';

@Controller('rule')
export class RulesController {
  constructor(
    @Inject(GetAllRulesUseCase)
    private readonly getAllRulesUseCase: GetAllRulesUseCase,
    @Inject(CreateRuleUseCase)
    private readonly createRuleUseCase: CreateRuleUseCase,
    @Inject(EditRuleUseCase) private readonly editRuleUseCase: EditRuleUseCase,
    @Inject(DeleteRuleUseCase)
    private readonly deleteRuleUseCase: DeleteRuleUseCase,
  ) {}

  @ApiOperation({
    summary: 'Create a new firewall rule',
    description:
      'Creates a new firewall rule with the provided details. Requires authentication.',
  })
  @Post()
  @Roles(Role.Operator)
  @RequirePermissions(Permission.RULES_CREATE)
  @HttpCode(HttpStatus.CREATED)
  @ApiBody({ type: CreateRuleDto })
  @ResponseMessage('Firewall rule created')
  @ApiCreatedEnvelope(CreateRuleResponseDto, 'Firewall rule created')
  @ApiError400('Validation failed')
  @ApiError401('Authorization header missing or invalid')
  @ApiError403('Insufficient permissions')
  @ApiError409('Firewall rule already exists')
  @ApiError429('Too many requests')
  @ApiError500('Server error while creating firewall rule')
  async createRule(
    @Body() createRuleDto: CreateRuleDto,
    @ExtractToken() accessToken: string,
  ): Promise<CreateRuleResponseDto> {
    const result = await this.createRuleUseCase.execute({
      ...createRuleDto,
      accessToken,
    });

    const rule = RuleResponseMapper.toDto(result.rule);

    return { rule };
  }

  @ApiOperation({
    summary: 'Get all firewall rules',
    description:
      'Retrieves a list of all firewall rules. Requires authentication.',
  })
  @Get()
  @Roles(Role.Viewer)
  @RequirePermissions(Permission.RULES_READ)
  @HttpCode(HttpStatus.OK)
  @ResponseMessage('List of firewall rules retrieved')
  @ApiOkEnvelope(GetAllRulesResponseDto, 'List of firewall rules retrieved')
  @ApiError401('Access token is missing, invalid, or expired')
  @ApiError403('Insufficient permissions to view firewall rules')
  @ApiError404('Firewall rules not found')
  @ApiError429('Too many requests')
  @ApiError500('Internal server error while retrieving firewall rules')
  async getAllRules(
    @Query() query: GetRulesQueryDto,
  ): Promise<GetAllRulesResponseDto> {
    const rules = await this.getAllRulesUseCase.execute(query);
    const mappedRules = rules.rules.map((rule) =>
      RuleResponseMapper.toDto(rule),
    );

    return { rules: mappedRules };
  }

  @ApiOperation({
    summary: 'Edit a firewall rule',
    description:
      'Edits an existing firewall rule with the provided details. Requires authentication.',
  })
  @Put(':id')
  @Roles(Role.Operator)
  @RequirePermissions(Permission.RULES_UPDATE)
  @HttpCode(HttpStatus.OK)
  @ApiBody({ type: EditRuleDto })
  @ResponseMessage('Firewall rule updated')
  @ApiOkEnvelope(EditRuleResponseDto, 'Firewall rule updated')
  @ApiError400('Validation failed')
  @ApiError401('Access token is missing, invalid, or expired')
  @ApiError403('Insufficient permissions to edit firewall rule')
  @ApiError404('Firewall rule not found')
  @ApiError409('Firewall rule name conflict')
  @ApiError429('Too many requests')
  @ApiError500('Internal server error while editing firewall rule')
  async editRule(
    @Body() editRuleDto: EditRuleDto,
    @Param('id') id: string,
  ): Promise<EditRuleResponseDto> {
    const rule = await this.editRuleUseCase.execute({ ...editRuleDto, id });

    return rule;
  }

  @ApiOperation({
    summary: 'Delete a firewall rule',
    description: 'Deletes a firewall rule by its ID. Requires authentication.',
  })
  @Delete(':id')
  @Roles(Role.Operator)
  @RequirePermissions(Permission.RULES_DELETE)
  @HttpCode(HttpStatus.NO_CONTENT)
  @ResponseMessage('Firewall rule deleted')
  @ApiNoContentEnvelope()
  @ApiError401('Access token is missing, invalid, or expired')
  @ApiError403('Insufficient permissions to delete firewall rule')
  @ApiError404('Firewall rule not found')
  @ApiError429('Too many requests')
  @ApiError500('Internal server error while deleting firewall rule')
  async deleteRule(@Param('id') id: string): Promise<void> {
    await this.deleteRuleUseCase.execute(id);
  }
}
