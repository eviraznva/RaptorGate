import { jest } from "@jest/globals";
import { Test, type TestingModule } from "@nestjs/testing";
import { NatRule } from "../../domain/entities/nat-rule.entity.js";
import { EntityNotFoundException } from "../../domain/exceptions/entity-not-found-exception.js";
import { NatConfigIsInvalidException } from "../../domain/exceptions/nat-config-is-invalid.exception.js";
import { NAT_RULES_REPOSITORY_TOKEN } from "../../domain/repositories/nat-rules.repository.js";
import { Priority } from "../../domain/value-objects/priority.vo.js";
import { NatProtocol } from "../../infrastructure/grpc/generated/common/common.js";
import { EditNatRuleUseCase } from "./edit-nat-rule.use-case.js";

describe("EditNatRuleUseCase", () => {
  let useCase: EditNatRuleUseCase;
  const repository = {
    save: jest.fn(),
    findById: jest.fn(),
  };

  const createNatRule = (): NatRule =>
    NatRule.createSnatRule({
      id: "5d375e76-b212-4c9e-8da0-601e5ebb3cd3",
      isActive: true,
      priority: Priority.create(10),
      protocol: NatProtocol.NAT_PROTOCOL_ALL,
      createdAt: new Date("2026-03-20T23:11:43.970Z"),
      updatedAt: new Date("2026-03-20T23:11:43.970Z"),
      snat: {
        srcCidr: "192.168.1.10/32",
        translatedIp: "172.16.0.20",
      },
    });

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

  it("throws when rule does not exist", async () => {
    repository.findById.mockResolvedValue(null);

    await expect(
      useCase.execute({
        id: "missing-id",
        priority: 20,
      }),
    ).rejects.toBeInstanceOf(EntityNotFoundException);

    expect(repository.save).not.toHaveBeenCalled();
  });

  it("updates selected fields and rebuilds rule", async () => {
    const natRule = createNatRule();
    repository.findById.mockResolvedValue(natRule);

    const result = await useCase.execute({
      id: natRule.getId(),
      isActive: false,
      priority: 20,
      protocol: NatProtocol.NAT_PROTOCOL_TCP,
    });

    expect(repository.save).toHaveBeenCalledWith(result.natRule);
    expect(result.natRule.getIsActive()).toBe(false);
    expect(result.natRule.getPriority().getValue()).toBe(20);
    expect(result.natRule.getProtocol()).toBe(NatProtocol.NAT_PROTOCOL_TCP);
    expect(result.natRule.getActionKind()).toBe("snat");
    expect(result.natRule.getUpdatedAt().getTime()).toBeGreaterThan(
      natRule.getUpdatedAt().getTime(),
    );
  });

  it("replaces action when action payload is provided", async () => {
    const natRule = createNatRule();
    repository.findById.mockResolvedValue(natRule);

    const result = await useCase.execute({
      id: natRule.getId(),
      action: {
        $case: "pat",
        pat: {
          dstIp: "198.51.100.22",
          dstPort: 443,
          translatedIp: "10.0.0.22",
          translatedPort: 8443,
        },
      },
    });

    expect(result.natRule.getActionKind()).toBe("pat");
    expect(repository.save).toHaveBeenCalledWith(result.natRule);
  });

  it("throws for invalid masquerade payload without outInterface", async () => {
    const natRule = createNatRule();
    repository.findById.mockResolvedValue(natRule);

    await expect(
      useCase.execute({
        id: natRule.getId(),
        action: { $case: "masquerade", masquerade: {} },
      }),
    ).rejects.toBeInstanceOf(NatConfigIsInvalidException);

    expect(repository.save).not.toHaveBeenCalled();
  });
});
