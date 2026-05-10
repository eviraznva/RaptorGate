import { jest } from '@jest/globals';
import { Test, TestingModule } from '@nestjs/testing';
import { NatRule } from '../../domain/entities/nat-rule.entity.js';
import { Priority } from '../../domain/value-objects/priority.vo.js';
import { NatProtocol } from '../../infrastructure/grpc/generated/common/common.js';
import { CreateNatRuleUseCase } from '../../application/use-cases/create-nat-rule.use-case.js';
import { DeleteNatRuleUseCase } from '../../application/use-cases/delete-nat-rule.use-case.js';
import { EditNatRuleUseCase } from '../../application/use-cases/edit-nat-rule.use-case.js';
import { GetAllNatRulesUseCase } from '../../application/use-cases/get-all-nat-rules.use-case.js';
import { NatRuleController } from './nat-rule.controller.js';

describe('NatRuleController', () => {
  let controller: NatRuleController;

  const createNatRuleUseCase = {
    execute: jest.fn(),
  };

  const getAllNatRulesUseCase = {
    execute: jest.fn(),
  };

  const editNatRuleUseCase = {
    execute: jest.fn(),
  };

  const deleteNatRuleUseCase = {
    execute: jest.fn(),
  };

  const natRule = NatRule.createDnatRule({
    id: '5d375e76-b212-4c9e-8da0-601e5ebb3cd3',
    isActive: true,
    priority: Priority.create(10),
    protocol: NatProtocol.NAT_PROTOCOL_ALL,
    createdAt: new Date('2026-03-20T23:11:43.970Z'),
    updatedAt: new Date('2026-03-20T23:11:43.970Z'),
    dnat: {
      dstCidr: '203.0.113.10/32',
      translatedIp: '10.0.0.10',
    },
  });

  beforeEach(async () => {
    createNatRuleUseCase.execute.mockReset();
    getAllNatRulesUseCase.execute.mockReset();
    editNatRuleUseCase.execute.mockReset();
    deleteNatRuleUseCase.execute.mockReset();

    const module: TestingModule = await Test.createTestingModule({
      controllers: [NatRuleController],
      providers: [
        {
          provide: CreateNatRuleUseCase,
          useValue: createNatRuleUseCase,
        },
        {
          provide: GetAllNatRulesUseCase,
          useValue: getAllNatRulesUseCase,
        },
        {
          provide: EditNatRuleUseCase,
          useValue: editNatRuleUseCase,
        },
        {
          provide: DeleteNatRuleUseCase,
          useValue: deleteNatRuleUseCase,
        },
      ],
    }).compile();

    controller = module.get(NatRuleController);
  });

  it('createNatRule calls use-case with dto and access token', async () => {
    createNatRuleUseCase.execute.mockResolvedValue({ natRule });

    const dto = {
      isActive: true,
      priority: 10,
      protocol: NatProtocol.NAT_PROTOCOL_ALL,
      action: {
        $case: 'dnat' as const,
        dnat: { dstCidr: '203.0.113.10/32', translatedIp: '10.0.0.10' },
      },
    };
    const accessToken = 'token-value';

    await controller.createNatRule(dto, accessToken);

    expect(createNatRuleUseCase.execute).toHaveBeenCalledWith({
      ...dto,
      accessToken,
    });
  });

  it('getAllNatRules returns mapped use-case response', async () => {
    getAllNatRulesUseCase.execute.mockResolvedValue({ natRules: [natRule] });

    const result = await controller.getAllNatRules({});

    expect(result.natRules).toHaveLength(1);
    expect(result.natRules[0].action.$case).toBe('dnat');
    expect(getAllNatRulesUseCase.execute).toHaveBeenCalledWith({});
  });

  it('editNatRule calls use-case with route id merged into dto', async () => {
    editNatRuleUseCase.execute.mockResolvedValue({ natRule });

    const id = 'rule-id-123';
    const dto = {
      priority: 25,
      isActive: false,
    };

    await controller.editNatRule(dto, id);

    expect(editNatRuleUseCase.execute).toHaveBeenCalledWith({
      id,
      ...dto,
    });
  });

  it('deleteNatRule calls use-case with id', async () => {
    deleteNatRuleUseCase.execute.mockResolvedValue(undefined);

    const id = 'rule-id-321';
    await controller.deleteNatRule(id);

    expect(deleteNatRuleUseCase.execute).toHaveBeenCalledWith(id);
  });
});
