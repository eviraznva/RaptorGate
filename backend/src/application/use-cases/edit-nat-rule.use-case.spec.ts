import { jest } from '@jest/globals';
import { Test, type TestingModule } from '@nestjs/testing';
import { NatRule } from '../../domain/entities/nat-rule.entity.js';
import { EntityNotFoundException } from '../../domain/exceptions/entity-not-found-exception.js';
import { NatConfigIsInvalidException } from '../../domain/exceptions/nat-config-is-invalid.exception.js';
import { NAT_RULES_REPOSITORY_TOKEN } from '../../domain/repositories/nat-rules.repository.js';
import { IpAddress } from '../../domain/value-objects/ip-address.vo.js';
import { NatType } from '../../domain/value-objects/nat-type.vo.js';
import { Port } from '../../domain/value-objects/port.vo.js';
import { Priority } from '../../domain/value-objects/priority.vo.js';
import { EditNatRuleUseCase } from './edit-nat-rule.use-case.js';

describe('EditNatRuleUseCase', () => {
  let useCase: EditNatRuleUseCase;
  const repository = {
    save: jest.fn(),
    findById: jest.fn(),
  };

  const createNatRule = (): NatRule =>
    NatRule.create(
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

  it('throws when rule does not exist', async () => {
    repository.findById.mockResolvedValue(null);

    await expect(
      useCase.execute({
        id: 'missing-id',
        priority: 20,
      }),
    ).rejects.toBeInstanceOf(EntityNotFoundException);

    expect(repository.save).not.toHaveBeenCalled();
  });

  it('updates selected fields and timestamp on existing rule', async () => {
    const natRule = createNatRule();
    repository.findById.mockResolvedValue(natRule);

    const previousUpdatedAt = natRule.getUpdatedAt();

    await useCase.execute({
      id: natRule.getId(),
      type: 'SNAT',
      isActive: false,
      sourceIp: '10.1.1.10',
      destinationIp: null,
      sourcePort: null,
      destinationPort: null,
      translatedIp: '10.2.2.20',
      translatedPort: null,
      priority: 20,
    });

    expect(repository.save).toHaveBeenCalledWith(natRule);
    expect(natRule.getIsActive()).toBe(false);
    expect(natRule.getPriority().getValue()).toBe(20);
    expect(natRule.getSourceIp()?.getValue).toBe('10.1.1.10');
    expect(natRule.getTranslatedIp()?.getValue).toBe('10.2.2.20');
    expect(natRule.getUpdatedAt().getTime()).toBeGreaterThan(
      previousUpdatedAt.getTime(),
    );
  });

  it('allows partial update without type validation', async () => {
    const natRule = createNatRule();
    repository.findById.mockResolvedValue(natRule);

    await useCase.execute({
      id: natRule.getId(),
      priority: 30,
    });

    expect(repository.save).toHaveBeenCalledWith(natRule);
    expect(natRule.getPriority().getValue()).toBe(30);
  });

  it('throws for invalid SNAT payload when sourceIp is missing', async () => {
    const natRule = createNatRule();
    repository.findById.mockResolvedValue(natRule);

    await expect(
      useCase.execute({
        id: natRule.getId(),
        type: 'SNAT',
        sourceIp: null,
        translatedIp: '172.16.0.21',
      }),
    ).rejects.toBeInstanceOf(NatConfigIsInvalidException);

    expect(repository.save).not.toHaveBeenCalled();
  });

  it('throws for invalid DNAT payload when sourceIp is provided', async () => {
    const natRule = NatRule.create(
      '77144f8f-c7b8-4ff4-988f-700f8cd3f937',
      NatType.create('DNAT'),
      true,
      null,
      IpAddress.create('203.0.113.10'),
      null,
      null,
      IpAddress.create('10.0.0.10'),
      null,
      Priority.create(15),
      new Date('2026-03-20T23:11:43.970Z'),
      new Date('2026-03-20T23:11:43.970Z'),
    );
    repository.findById.mockResolvedValue(natRule);

    await expect(
      useCase.execute({
        id: natRule.getId(),
        type: 'DNAT',
        destinationIp: '203.0.113.11',
        translatedIp: '10.0.0.11',
        sourceIp: '192.168.10.10',
      }),
    ).rejects.toBeInstanceOf(NatConfigIsInvalidException);

    expect(repository.save).not.toHaveBeenCalled();
  });

  it('throws for invalid PAT payload when destinationPort is missing', async () => {
    const natRule = NatRule.create(
      '6cecc3f8-8432-461a-8c6e-f49b6439a5d8',
      NatType.create('PAT'),
      true,
      null,
      IpAddress.create('198.51.100.22'),
      null,
      Port.create(8080),
      IpAddress.create('10.0.0.22'),
      Port.create(80),
      Priority.create(5),
      new Date('2026-03-20T23:11:43.970Z'),
      new Date('2026-03-20T23:11:43.970Z'),
    );
    repository.findById.mockResolvedValue(natRule);

    await expect(
      useCase.execute({
        id: natRule.getId(),
        type: 'PAT',
        destinationIp: '198.51.100.23',
        destinationPort: null,
        translatedIp: '10.0.0.23',
        translatedPort: 81,
      }),
    ).rejects.toBeInstanceOf(NatConfigIsInvalidException);

    expect(repository.save).not.toHaveBeenCalled();
  });
});
