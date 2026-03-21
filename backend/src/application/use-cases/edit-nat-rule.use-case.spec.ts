import { NAT_RULES_REPOSITORY_TOKEN } from 'src/domain/repositories/nat-rules.repository';
import { Priority } from 'src/domain/value-objects/priority.vo';
import { IpAddress } from 'src/domain/value-objects/ip-address.vo';
import { NatType } from 'src/domain/value-objects/nat-type.vo';
import { EditNatRuleUseCase } from './edit-nat-rule.use-case';
import { NatRule } from 'src/domain/entities/nat-rule.entity';
import { Test, TestingModule } from '@nestjs/testing';

describe('EditNatRuleUseCase', () => {
  let useCase: EditNatRuleUseCase;
  const repository = {
    save: jest.fn(),
    findById: jest.fn(),
  };

  beforeEach(async () => {
    repository.save.mockReset();
    repository.findById.mockReset();

    const module: TestingModule = await Test.createTestingModule({
      providers: [
        EditNatRuleUseCase,
        {
          provide: NAT_RULES_REPOSITORY_TOKEN,
          useValue: repository,
        },
      ],
    }).compile();

    useCase = module.get(EditNatRuleUseCase);
  });

  it('persists a priority-only update against an existing rule', async () => {
    const natRule = NatRule.create(
      '5d375e76-b212-4c9e-8da0-601e5ebb3cd3',
      NatType.create('SNAT'),
      true,
      IpAddress.create('192.168.1.10'),
      null,
      null,
      null,
      IpAddress.create('172.16.0.20'),
      null,
      Priority.create(10),
      new Date('2026-03-20T23:11:43.970Z'),
      new Date('2026-03-20T23:11:43.970Z'),
    );

    repository.findById.mockResolvedValue(natRule);
    repository.save.mockResolvedValue(undefined);

    await useCase.execute({
      id: natRule.getId(),
      type: 'SNAT',
      priority: 20,
    });

    expect(repository.save).toHaveBeenCalledWith(natRule);
    expect(natRule.getPriority().getValue()).toBe(20);
  });
});
