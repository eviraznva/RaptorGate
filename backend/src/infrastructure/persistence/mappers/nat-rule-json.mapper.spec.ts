import { describe, expect, it } from "@jest/globals";
import { NatConfigIsInvalidException } from "../../../domain/exceptions/nat-config-is-invalid.exception.js";
import { NatRuleJsonMapper } from "./nat-rule-json.mapper.js";

describe("NatRuleJsonMapper", () => {
  it("rejects proto NAT record without action", () => {
    expect(() =>
      NatRuleJsonMapper.toDomain({
        id: "5d375e76-b212-4c9e-8da0-601e5ebb3cd3",
        isActive: true,
        priority: 10,
        protocol: "NAT_PROTOCOL_ALL",
        createdAt: "2026-03-20T23:11:43.970Z",
        updatedAt: "2026-03-20T23:11:43.970Z",
        createdBy: "8d3fae59-d1b7-4812-9f31-caf772a9252c",
      } as never),
    ).toThrow(NatConfigIsInvalidException);
  });

  it("converts legacy SNAT record into action oneof", () => {
    const rule = NatRuleJsonMapper.toDomain({
      id: "5d375e76-b212-4c9e-8da0-601e5ebb3cd3",
      type: "SNAT",
      isActive: true,
      srcIp: "192.168.1.10",
      dstIp: null,
      srcPort: null,
      dstPort: null,
      translatedIp: "198.51.100.10",
      translatedPort: null,
      priority: 10,
      createdAt: "2026-03-20T23:11:43.970Z",
      updatedAt: "2026-03-20T23:11:43.970Z",
      createdBy: "8d3fae59-d1b7-4812-9f31-caf772a9252c",
    });

    expect(rule.getActionKind()).toBe("snat");
    expect(rule.getAction()).toEqual(
      expect.objectContaining({
        $case: "snat",
        snat: expect.objectContaining({
          srcCidr: "192.168.1.10/32",
          translatedIp: "198.51.100.10",
        }),
      }),
    );
  });

  it("accepts legacy DNAT shape without $case top-level", () => {
    const legacyRecord = {
      id: "test-1",
      isActive: true,
      priority: 10,
      protocol: "NAT_PROTOCOL_ALL",
      createdAt: "2026-03-20T23:11:43.970Z",
      updatedAt: "2026-03-20T23:11:43.970Z",
      createdBy: "8d3fae59-d1b7-4812-9f31-caf772a9252c",
      action: { dnat: { dstCidr: "10.0.0.0/24", translatedIp: "10.0.0.1" } },
    };

    const domain = NatRuleJsonMapper.toDomain(legacyRecord as never);
    expect(domain.getAction().$case).toBe("dnat");
    expect((domain.getAction() as any).dnat.dstCidr).toBe("10.0.0.0/24");
  });

  it("accepts legacy PAT shape without $case top-level", () => {
    const legacyRecord = {
      id: "test-2",
      isActive: true,
      priority: 20,
      protocol: "NAT_PROTOCOL_ALL",
      createdAt: "2026-03-20T23:11:43.970Z",
      updatedAt: "2026-03-20T23:11:43.970Z",
      createdBy: "8d3fae59-d1b7-4812-9f31-caf772a9252c",
      action: {
        pat: {
          dstIp: "192.168.1.10",
          dstPort: 80,
          translatedIp: "10.0.0.5",
          translatedPort: 8080,
        },
      },
    };

    const domain = NatRuleJsonMapper.toDomain(legacyRecord as never);
    expect(domain.getAction().$case).toBe("pat");
    expect((domain.getAction() as any).pat.dstPort.value).toBe(80);
  });

  it("accepts proper proto shape with explicit $case", () => {
    const protoRecord = {
      id: "test-3",
      isActive: true,
      priority: 30,
      protocol: "NAT_PROTOCOL_ALL",
      createdAt: "2026-03-20T23:11:43.970Z",
      updatedAt: "2026-03-20T23:11:43.970Z",
      createdBy: "8d3fae59-d1b7-4812-9f31-caf772a9252c",
      action: {
        $case: "snat",
        snat: { srcCidr: "172.16.0.0/16", translatedIp: "172.16.0.254" },
      },
    };

    const domain = NatRuleJsonMapper.toDomain(protoRecord as never);
    expect(domain.getAction().$case).toBe("snat");
    expect((domain.getAction() as any).snat.srcCidr).toBe(
      "172.16.0.0/16",
    );
  });
});
