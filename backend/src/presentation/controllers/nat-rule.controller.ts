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
import { GetAllNatRulesUseCase } from '../../application/use-cases/get-all-nat-rules.use-case.js';
import { CreateNatRuleUseCase } from '../../application/use-cases/create-nat-rule.use-case.js';
import { DeleteNatRuleUseCase } from '../../application/use-cases/delete-nat-rule.use-case.js';
import { EditNatRuleUseCase } from '../../application/use-cases/edit-nat-rule.use-case.js';
import { ExtractToken } from '../../infrastructure/decorators/extract-token.decorator.js';
import { GetAllNatRulesResponseDto } from '../dtos/get-all-nat-rules-response.dto.js';
import { Roles } from '../../infrastructure/decorators/roles.decorator.js';
import { Permission } from '../../domain/enums/permissions.enum.js';
import { CreateNatRuleDto } from '../dtos/create-nat-rule.dto.js';
import { EditNatRuleDto } from '../dtos/edit-nat-rule.dto.js';
import { Role } from '../../domain/enums/role.enum.js';
import { ApiOperation } from '@nestjs/swagger';

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
  async createNatRule(
    @Body() createNatRuleDto: CreateNatRuleDto,
    @ExtractToken() accessToken: string,
  ): Promise<void> {
    await this.createNatRuleUseCase.execute({
      ...createNatRuleDto,
      accessToken,
    });
  }

  @ApiOperation({
    summary: 'Get all NAT rules',
    description:
      'Gets a list of all NAT rules. Requires Viewer role and NAT_RULES_READ permission.',
  })
  @Get()
  @Roles(Role.Viewer)
  @RequirePermissions(Permission.NAT_RULES_READ)
  async getAllNatRules(): Promise<GetAllNatRulesResponseDto> {
    const natRules = await this.getAllNatRulesUseCase.execute();

    return natRules;
  }

  @ApiOperation({
    summary: 'Edit an existing NAT rule',
    description:
      'Edits an existing NAT rule with the specified parameters. Requires Operator role and NAT_RULES_EDIT permission.',
  })
  @Put(':id')
  @Roles(Role.Operator)
  @RequirePermissions(Permission.NAT_RULES_UPDATE)
  async editNatRule(@Body() dto: EditNatRuleDto, @Param('id') id: string) {
    await this.editNatRuleUseCase.execute({
      id,
      ...dto,
    });
  }

  @ApiOperation({
    summary: 'Delete a NAT rule',
    description:
      'Deletes a NAT rule by its ID. Requires Operator role and NAT_RULES_DELETE permission.',
  })
  @Delete(':id')
  @Roles(Role.Operator)
  @RequirePermissions(Permission.NAT_RULES_DELETE)
  async deleteNatRule(@Param('id') id: string): Promise<void> {
    await this.deleteNatRuleUseCase.execute(id);
  }
}
