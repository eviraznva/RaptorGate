import { describe, expect, it } from "bun:test";
import {
  validateBypassDomainInput,
  validateDecryptionFailurePolicy,
} from "../src/components/tlsInspection/validation";

describe("TLS inspection bypass validation", () => {
  it("accepts regular domains and wildcard domains", () => {
    expect(validateBypassDomainInput("www.google.com")).toEqual([]);
    expect(validateBypassDomainInput("*.example.com")).toEqual([]);
  });

  it("rejects invalid domains", () => {
    expect(validateBypassDomainInput("google")).toContain(
      "Domain must be a valid FQDN or wildcard domain.",
    );
  });

  it("accepts valid decryption failure policy values", () => {
    expect(
      validateDecryptionFailurePolicy({
        failureThreshold: 3,
        failureWindowSec: 60,
        localExclusionTtlSec: 86400,
        maxEntries: 4096,
      }),
    ).toEqual([]);
  });

  it("rejects invalid decryption failure policy numeric values", () => {
    const errors = validateDecryptionFailurePolicy({
      failureThreshold: 0,
      failureWindowSec: 0,
      localExclusionTtlSec: 0,
      maxEntries: 0,
    });

    expect(errors).toContain("Failure threshold must be in range 1..1000.");
    expect(errors).toContain("Failure window must be at least 1 second.");
    expect(errors).toContain("Local exclusion TTL must be at least 1 second.");
    expect(errors).toContain("Max entries must be at least 1.");
  });
});
