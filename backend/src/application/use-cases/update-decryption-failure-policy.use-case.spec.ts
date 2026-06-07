import { ConfigurationSnapshot } from "../../domain/entities/configuration-snapshot.entity.js";
import type { IConfigSnapshotRepository } from "../../domain/repositories/config-snapshot.repository.js";
import { Checksum } from "../../domain/value-objects/checksum.vo.js";
import { SnapshotType } from "../../domain/value-objects/snapshot-type.vo.js";
import type { IConfigSnapshotPushService } from "../ports/config-snapshot-push-service.interface.js";
import type { ITokenService } from "../ports/token-service.interface.js";
import { UpdateDecryptionFailurePolicyUseCase } from "./update-decryption-failure-policy.use-case.js";

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

describe("UpdateDecryptionFailurePolicyUseCase", () => {
  it("persists cacheAndBypass as an explicit policy and pushes a new snapshot", async () => {
    const activeSnapshot = snapshot({
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
    });
    const saved: ConfigurationSnapshot[] = [];
    const repository: IConfigSnapshotRepository = {
      save: jest.fn(async (configSnapshot: ConfigurationSnapshot) => {
        saved.push(configSnapshot);
      }),
      findActiveSnapshot: jest.fn().mockResolvedValue(activeSnapshot),
      findAllSnapshots: jest.fn().mockResolvedValue([activeSnapshot]),
      findById: jest.fn(),
    };
    const pushService: IConfigSnapshotPushService = {
      pushActiveConfigSnapshot: jest.fn(),
      factoryReset: jest.fn(),
    };
    const tokenService: ITokenService = {
      generateAccessToken: jest.fn(),
      generateRefreshToken: jest.fn(),
      generateTokenPair: jest.fn(),
      verifyAccessToken: jest.fn(),
      decodeAccessToken: jest.fn().mockReturnValue({
        sub: "operator-1",
        username: "operator",
      }),
    };
    const useCase = new UpdateDecryptionFailurePolicyUseCase(
      repository,
      pushService,
      tokenService,
    );

    const response = await useCase.execute({
      accessToken: "token",
      enabled: true,
      failureThreshold: 2,
      failureWindowSec: 30,
      localExclusionTtlSec: 600,
      maxEntries: 128,
      action: "cacheAndBypass",
    });

    expect(response.decryptionFailurePolicy.action).toBe("cacheAndBypass");
    expect(activeSnapshot.getIsActive()).toBe(false);
    expect(saved).toHaveLength(2);
    expect(
      saved[0].deserializePayload().bundle.tls_inspection_policy
        ?.decryption_failure_cache,
    ).toMatchObject({
      enabled: true,
      failure_threshold: 2,
      failure_window_sec: 30,
      local_exclusion_ttl_sec: 600,
      max_entries: 128,
      action: "cache_and_bypass",
    });
    expect(pushService.pushActiveConfigSnapshot).toHaveBeenCalledWith(
      saved[0],
      "decryption_failure_policy_update",
    );
  });

  it("persists block as an explicit security policy without rewriting exclusion lists", async () => {
    const activeSnapshot = snapshot({
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
        tls_inspection_policy: {
          known_pinned_domains: ["bank.example"],
          decryption_exclusions: ["updates.example"],
          decryption_failure_cache: {
            version: 1,
            enabled: true,
            failure_threshold: 2,
            failure_window_sec: 30,
            local_exclusion_ttl_sec: 600,
            max_entries: 128,
            action: "cache_and_bypass",
          },
        },
      },
    });
    const saved: ConfigurationSnapshot[] = [];
    const repository: IConfigSnapshotRepository = {
      save: jest.fn(async (configSnapshot: ConfigurationSnapshot) => {
        saved.push(configSnapshot);
      }),
      findActiveSnapshot: jest.fn().mockResolvedValue(activeSnapshot),
      findAllSnapshots: jest.fn().mockResolvedValue([activeSnapshot]),
      findById: jest.fn(),
    };
    const pushService: IConfigSnapshotPushService = {
      pushActiveConfigSnapshot: jest.fn(),
      factoryReset: jest.fn(),
    };
    const tokenService: ITokenService = {
      generateAccessToken: jest.fn(),
      generateRefreshToken: jest.fn(),
      generateTokenPair: jest.fn(),
      verifyAccessToken: jest.fn(),
      decodeAccessToken: jest.fn().mockReturnValue({
        sub: "operator-1",
        username: "operator",
      }),
    };
    const useCase = new UpdateDecryptionFailurePolicyUseCase(
      repository,
      pushService,
      tokenService,
    );

    const response = await useCase.execute({
      accessToken: "token",
      enabled: true,
      failureThreshold: 3,
      failureWindowSec: 60,
      localExclusionTtlSec: 86400,
      maxEntries: 4096,
      action: "block",
    });

    const savedPolicy = saved[0].deserializePayload().bundle.tls_inspection_policy;
    expect(response.decryptionFailurePolicy.action).toBe("block");
    expect(savedPolicy?.known_pinned_domains).toEqual(["bank.example"]);
    expect(savedPolicy?.decryption_exclusions).toEqual(["updates.example"]);
    expect(savedPolicy?.decryption_failure_cache).toMatchObject({
      failure_threshold: 3,
      failure_window_sec: 60,
      local_exclusion_ttl_sec: 86400,
      max_entries: 4096,
      action: "block",
    });
    expect(pushService.pushActiveConfigSnapshot).toHaveBeenCalledWith(
      saved[0],
      "decryption_failure_policy_update",
    );
  });
});
