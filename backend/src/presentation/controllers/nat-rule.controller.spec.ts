import { DeleteNatRuleUseCase } from 'src/application/use-cases/delete-nat-rule.use-case';
import { GetAllNatRulesUseCase } from 'src/application/use-cases/get-all-nat-rules.use-case';
import { EditNatRuleUseCase } from 'src/application/use-cases/edit-nat-rule.use-case';
import { CreateNatRuleUseCase } from 'src/application/use-cases/create-nat-rule.use-case';
import { TestingModule, Test } from '@nestjs/testing';
import { NatRuleController } from './nat-rule.controller';

describe('NatRuleController', () => {
  let controller: NatRuleController;
  const createNatRuleUseCase = { execute: jest.fn() };
  const getAllNatRulesUseCase = { execute: jest.fn() };
  const editNatRuleUseCase = { execute: jest.fn() };
  const deleteNatRuleUseCase = { execute: jest.fn() };

  beforeEach(async () => {
    jest.clearAllMocks();

    const module: TestingModule = await Test.createTestingModule({
      controllers: [NatRuleController],
      providers: [
        { provide: CreateNatRuleUseCase, useValue: createNatRuleUseCase },
        { provide: GetAllNatRulesUseCase, useValue: getAllNatRulesUseCase },
        { provide: EditNatRuleUseCase, useValue: editNatRuleUseCase },
        { provide: DeleteNatRuleUseCase, useValue: deleteNatRuleUseCase },
      ],
    }).compile();

    controller = module.get(NatRuleController);
  });

  it('normalizes UI field aliases before invoking the edit use case', async () => {
    await controller.editNatRule(
      {
        type: 'SNAT',
        priority: 20,
        srcIp: '192.168.1.10',
        dstIp: null,
        srcPort: null,
        dstPort: null,
        translatedIp: '172.16.0.20',
        translatedPort: null,
        createdAt: '2026-03-20T23:11:43.970Z',
        updatedAt: '2026-03-20T23:11:43.970Z',
        createdBy: '00000000-0000-4000-8000-000000000001',
      } as any,
      '5d375e76-b212-4c9e-8da0-601e5ebb3cd3',
    );

    expect(editNatRuleUseCase.execute).toHaveBeenCalledWith({
      id: '5d375e76-b212-4c9e-8da0-601e5ebb3cd3',
      type: 'SNAT',
      isActive: undefined,
      sourceIp: '192.168.1.10',
      destinationIp: null,
      sourcePort: null,
      destinationPort: null,
      translatedIp: '172.16.0.20',
      translatedPort: null,
      priority: 20,
    });
  });
});
