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
import { RequirePermissions } from 'src/infrastructure/decorators/require-permissions.decorator';
import { GetAllRulesUseCase } from 'src/application/use-cases/get-all-rules.use-case';
import { ExtractToken } from 'src/infrastructure/decorators/extract-token.decorator';
import { CreateRuleUseCase } from 'src/application/use-cases/create-rule.use-case';
import { DeleteRuleUseCase } from 'src/application/use-cases/delete-rule.use-case';
import { EditRuleUseCase } from 'src/application/use-cases/edit-rule.use-case';
import { Roles } from 'src/infrastructure/decorators/roles.decorator';
import { Permission } from 'src/domain/enums/permissions.enum';
import { CreateRuleDto } from '../dtos/create-rule.dto';
import { EditRuleDto } from '../dtos/edit-rule.dto';
import { Role } from 'src/domain/enums/role.enum';
import { ApiOperation } from '@nestjs/swagger';

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
  async getAllRules() {
    const rules = await this.getAllRulesUseCase.execute();
    return { rules };
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
