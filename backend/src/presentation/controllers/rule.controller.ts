import {
  Body,
  Controller,
  Delete,
  Get,
  Inject,
  Param,
  Post,
  Put,
} from '@nestjs/common';
import { RequirePermissions } from '../../infrastructure/decorators/require-permissions.decorator.js';
import { GetAllRulesUseCase } from '../../application/use-cases/get-all-rules.use-case.js';
import { ExtractToken } from '../../infrastructure/decorators/extract-token.decorator.js';
import { CreateRuleUseCase } from '../../application/use-cases/create-rule.use-case.js';
import { DeleteRuleUseCase } from '../../application/use-cases/delete-rule.use-case.js';
import { EditRuleUseCase } from '../../application/use-cases/edit-rule.use-case.js';
import { Roles } from '../../infrastructure/decorators/roles.decorator.js';
import { Permission } from '../../domain/enums/permissions.enum.js';
import { CreateRuleDto } from '../dtos/create-rule.dto.js';
import { EditRuleDto } from '../dtos/edit-rule.dto.js';
import { Role } from '../../domain/enums/role.enum.js';
import { ApiOperation } from '@nestjs/swagger';
import { GetAllRulesResponseDto } from '../dtos/get-all-rules-response.dto.js';

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
  async createRule(
    @Body() createRuleDto: CreateRuleDto,
    @ExtractToken() accessToken: string,
  ) {
    await this.createRuleUseCase.execute({ ...createRuleDto, accessToken });
  }

  @ApiOperation({
    summary: 'Get all firewall rules',
    description:
      'Retrieves a list of all firewall rules. Requires authentication.',
  })
  @Get()
  @Roles(Role.Viewer)
  @RequirePermissions(Permission.RULES_READ)
  async getAllRules(): Promise<GetAllRulesResponseDto> {
    const rules = await this.getAllRulesUseCase.execute();
    return rules;
  }

  @ApiOperation({
    summary: 'Edit a firewall rule',
    description:
      'Edits an existing firewall rule with the provided details. Requires authentication.',
  })
  @Put(':id')
  @Roles(Role.Operator)
  @RequirePermissions(Permission.RULES_UPDATE)
  async editRule(@Body() editRuleDto: EditRuleDto, @Param('id') id: string) {
    await this.editRuleUseCase.execute({ ...editRuleDto, id });
  }

  @ApiOperation({
    summary: 'Delete a firewall rule',
    description: 'Deletes a firewall rule by its ID. Requires authentication.',
  })
  @Delete(':id')
  @Roles(Role.Operator)
  @RequirePermissions(Permission.RULES_DELETE)
  async deleteRule(@Param('id') id: string): Promise<void> {
    await this.deleteRuleUseCase.execute(id);
  }
}
