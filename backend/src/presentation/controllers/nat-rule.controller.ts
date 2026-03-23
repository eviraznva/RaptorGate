import { CreateNatRuleUseCase } from 'src/application/use-cases/create-nat-rule.use-case';
import { ExtractToken } from 'src/infrastructure/decorators/extract-token.decorator';
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
import { GetAllNatRulesUseCase } from 'src/application/use-cases/get-all-nat-rules.use-case';
import { DeleteNatRuleUseCase } from 'src/application/use-cases/delete-nat-rule.use-case';
import { EditNatRuleUseCase } from 'src/application/use-cases/edit-nat-rule.use-case';
import { GetAllNatRulesResponseDto } from '../dtos/get-all-nat-rules-response.dto';
import { Roles } from 'src/infrastructure/decorators/roles.decorator';
import { Permission } from 'src/domain/enums/permissions.enum';
import { CreateNatRuleDto } from '../dtos/create-nat-rule.dto';
import { EditNatRuleDto } from '../dtos/edit-nat-rule.dto';
import { Role } from 'src/domain/enums/role.enum';
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
