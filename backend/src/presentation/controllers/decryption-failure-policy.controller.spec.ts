import { Test, type TestingModule } from "@nestjs/testing";
import { GetDecryptionFailurePolicyUseCase } from "../../application/use-cases/get-decryption-failure-policy.use-case.js";
import { UpdateDecryptionFailurePolicyUseCase } from "../../application/use-cases/update-decryption-failure-policy.use-case.js";
import { DecryptionFailurePolicyController } from "./decryption-failure-policy.controller.js";

describe("DecryptionFailurePolicyController", () => {
  let controller: DecryptionFailurePolicyController;

  const getDecryptionFailurePolicyUseCase = {
    execute: jest.fn(),
  };
  const updateDecryptionFailurePolicyUseCase = {
    execute: jest.fn(),
  };

  beforeEach(async () => {
    getDecryptionFailurePolicyUseCase.execute.mockReset();
    updateDecryptionFailurePolicyUseCase.execute.mockReset();

    const module: TestingModule = await Test.createTestingModule({
      controllers: [DecryptionFailurePolicyController],
      providers: [
        {
          provide: GetDecryptionFailurePolicyUseCase,
          useValue: getDecryptionFailurePolicyUseCase,
        },
        {
          provide: UpdateDecryptionFailurePolicyUseCase,
          useValue: updateDecryptionFailurePolicyUseCase,
        },
      ],
    }).compile();

    controller = module.get(DecryptionFailurePolicyController);
  });

  it("returns the use-case response for GET", async () => {
    const response = {
      decryptionFailurePolicy: {
        enabled: true,
        failureThreshold: 3,
        failureWindowSec: 60,
        localExclusionTtlSec: 86400,
        maxEntries: 4096,
        action: "block" as const,
      },
    };
    getDecryptionFailurePolicyUseCase.execute.mockResolvedValue(response);

    await expect(controller.getDecryptionFailurePolicy()).resolves.toBe(response);
  });

  it("passes DTO and access token to the update use-case", async () => {
    const dto = {
      enabled: true,
      failureThreshold: 2,
      failureWindowSec: 30,
      localExclusionTtlSec: 600,
      maxEntries: 128,
      action: "cacheAndBypass" as const,
    };
    updateDecryptionFailurePolicyUseCase.execute.mockResolvedValue({
      decryptionFailurePolicy: dto,
    });

    await controller.updateDecryptionFailurePolicy(dto, "access-token");

    expect(updateDecryptionFailurePolicyUseCase.execute).toHaveBeenCalledWith({
      ...dto,
      accessToken: "access-token",
    });
  });
});
