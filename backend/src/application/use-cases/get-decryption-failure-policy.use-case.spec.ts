import { ConfigurationSnapshot } from "../../domain/entities/configuration-snapshot.entity.js";
import type { IConfigSnapshotRepository } from "../../domain/repositories/config-snapshot.repository.js";
import { Checksum } from "../../domain/value-objects/checksum.vo.js";
import { SnapshotType } from "../../domain/value-objects/snapshot-type.vo.js";
import { GetDecryptionFailurePolicyUseCase } from "./get-decryption-failure-policy.use-case.js";

function snapshot(payload: unknown): ConfigurationSnapshot {
  return ConfigurationSnapshot.create(
    "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa",
    1,
    SnapshotType.create("auto_save"),
    Checksum.create("0".repeat(64)),
    true,
    payload,
    "test",
    new Date("2026-06-07T00:00:00.000Z"),
    "tester",
  );
}

describe("GetDecryptionFailurePolicyUseCase", () => {
  it("returns default security-first policy when active snapshot has no TLS policy", async () => {
    const repository: IConfigSnapshotRepository = {
      save: jest.fn(),
      findActiveSnapshot: jest.fn().mockResolvedValue(snapshot({
        bundle: {
          rules: { items: [] },
          zones: { items: [] },
          zone_interfaces: { items: [] },
          zone_pairs: { items: [] },
          nat_rules: { items: [] },
          dns_blacklist: { items: [] },
          ssl_bypass_list: { items: [] },
          ips_signatures: { items: [] },
          ml_model: null,
          firewall_certificates: { items: [] },
          users: { items: [] },
        },
      })),
      findAllSnapshots: jest.fn(),
      findById: jest.fn(),
    };
    const useCase = new GetDecryptionFailurePolicyUseCase(repository);

    await expect(useCase.execute()).resolves.toEqual({
      decryptionFailurePolicy: {
        enabled: true,
        failureThreshold: 3,
        failureWindowSec: 60,
        localExclusionTtlSec: 86400,
        maxEntries: 4096,
        action: "block",
      },
    });
  });
});
