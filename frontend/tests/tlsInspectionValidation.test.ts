import { describe, expect, it } from "bun:test";
import { validateBypassDomainInput } from "../src/components/tlsInspection/validation";

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
});
