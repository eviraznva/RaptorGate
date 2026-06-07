import {
  DEFAULT_TLS_INSPECTION_POLICY,
  normalizeTlsInspectionPolicy,
} from "./config-snapshot-payload.interface.js";

describe("normalizeTlsInspectionPolicy", () => {
  it("defaults decryption failure action to block", () => {
    expect(DEFAULT_TLS_INSPECTION_POLICY.decryption_failure_cache.action).toBe(
      "block",
    );
    expect(
      normalizeTlsInspectionPolicy().decryption_failure_cache.action,
    ).toBe("block");
  });

  it("does not convert legacy known pinned domains into decryption exclusions", () => {
    const policy = normalizeTlsInspectionPolicy({
      known_pinned_domains: ["bank.example"],
    });

    expect(policy.known_pinned_domains).toEqual(["bank.example"]);
    expect(policy.decryption_exclusions).toEqual([]);
  });
});
