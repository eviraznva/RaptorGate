import { ClientGrpc } from "@nestjs/microservices";
import { of } from "rxjs";
import { NatRule } from "src/domain/entities/nat-rule.entity.js";
import { NatConfigIsInvalidException } from "src/domain/exceptions/nat-config-is-invalid.exception.js";
import { Priority } from "src/domain/value-objects/priority.vo.js";
import { ConfigurationSnapshot } from "../../domain/entities/configuration-snapshot.entity.js";
import { Checksum } from "../../domain/value-objects/checksum.vo.js";
import { SnapshotType } from "../../domain/value-objects/snapshot-type.vo.js";
import { NatProtocol } from "../grpc/generated/common/common.js";
import { SmtpMatchAction as GrpcSmtpMatchAction } from "../grpc/generated/config/config_models.js";
import { GrpcConfigSnapshotPushService } from "./grpc-config-snapshot-push.service.js";

function methodObject(methods: Record<string, unknown>) {
  return methods;
}

function makeSnapshot(natRule: NatRule): ConfigurationSnapshot {
  return ConfigurationSnapshot.create(
    "f0870f37-8b24-4c08-bff0-90c4270f5858",
    1,
    SnapshotType.create("auto_save"),
    Checksum.create("a".repeat(64)),
    true,
    {
      bundle: {
        rules: { items: [] },
        zones: { items: [] },
        zone_interfaces: { items: [] },
        zone_pairs: { items: [] },
        nat_rules: { items: [natRule] },
        dns_blacklist: { items: [] },
        ssl_bypass_list: { items: [] },
        ips_signatures: { items: [] },
        ml_model: null,
        firewall_certificates: { items: [] },
        users: { items: [] },
      },
    },
    null,
    new Date("2026-03-20T23:11:43.970Z"),
    "8d3fae59-d1b7-4812-9f31-caf772a9252c",
  );
}

describe("GrpcConfigSnapshotPushService", () => {
  it("rejects NAT rule without action before gRPC push", async () => {
    const pushActiveConfigSnapshot = jest.fn(() => of({ accepted: true }));
    const service = new GrpcConfigSnapshotPushService({
      getService: () => ({
        pushActiveConfigSnapshot,
      }),
    } as unknown as ClientGrpc);
    service.onModuleInit();

    const natRule = NatRule.createSnatRule({
      id: "5d375e76-b212-4c9e-8da0-601e5ebb3cd3",
      isActive: true,
      priority: Priority.create(10),
      protocol: NatProtocol.NAT_PROTOCOL_ALL,
      createdAt: new Date("2026-03-20T23:11:43.970Z"),
      updatedAt: new Date("2026-03-20T23:11:43.970Z"),
      snat: {
        srcCidr: "192.168.1.10/32",
        translatedIp: "198.51.100.10",
      },
    });
    (natRule as unknown as { action: undefined }).action = undefined;

    await expect(
      service.pushActiveConfigSnapshot(makeSnapshot(natRule), "apply"),
    ).rejects.toBeInstanceOf(NatConfigIsInvalidException);
    expect(pushActiveConfigSnapshot).not.toHaveBeenCalled();
  });
});

describe("GrpcConfigSnapshotPushService", () => {
  it("serializes zone interface oneof in proto-loader shape", async () => {
    let request: any;
    const client = {
      getService: () => ({
        pushActiveConfigSnapshot: (value: any) => {
          request = value;
          return of({ accepted: true, appliedSnapshotId: value.snapshot.id });
        },
      }),
    } as any;
    const service = new GrpcConfigSnapshotPushService(client);
    service.onModuleInit();
    const zoneInterface = methodObject({
      getId: () => "55555555-5555-4555-8555-555555555555",
      getZoneId: () => "11111111-1111-4111-8111-111111111111",
      getVlanId: () => null,
      getInterfaceName: () => "eth2",
      getStatus: () => "active",
      getAddresses: () => ["192.168.20.254/24"],
      getSniffed: () => true,
      getParentInterfaceId: () => null,
    });
    const snapshot = ConfigurationSnapshot.create(
      "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa",
      1,
      SnapshotType.create("auto_save"),
      Checksum.create("0".repeat(64)),
      true,
      {
        bundle: {
          rules: { items: [] },
          zones: { items: [] },
          zone_interfaces: { items: [zoneInterface] },
          zone_pairs: { items: [] },
          nat_rules: { items: [] },
          dns_blacklist: { items: [] },
          ssl_bypass_list: { items: [] },
          ips_signatures: { items: [] },
          ml_model: null,
          firewall_certificates: { items: [] },
          tls_inspection_policy: undefined,
        },
      },
      "test",
      new Date("2026-05-09T00:00:00.000Z"),
      "tester",
    );

    await service.pushActiveConfigSnapshot(snapshot, "apply");

    expect(request.snapshot.bundle.zoneInterfaces[0]).toMatchObject({
      id: "55555555-5555-4555-8555-555555555555",
      zoneId: "11111111-1111-4111-8111-111111111111",
      physical: { interfaceName: "eth2" },
    });
    expect(request.snapshot.bundle.zoneInterfaces[0].kind).toBeUndefined();
  });

  it("limits physical interfaces to one desired address in the gRPC payload", async () => {
    let request: any;
    const client = {
      getService: () => ({
        pushActiveConfigSnapshot: (value: any) => {
          request = value;
          return of({ accepted: true, appliedSnapshotId: value.snapshot.id });
        },
      }),
    } as any;
    const service = new GrpcConfigSnapshotPushService(client);
    service.onModuleInit();
    const zoneInterface = methodObject({
      getId: () => "55555555-5555-4555-8555-555555555555",
      getZoneId: () => "11111111-1111-4111-8111-111111111111",
      getVlanId: () => null,
      getInterfaceName: () => "eth2",
      getStatus: () => "active",
      getAddresses: () => ["fe80::1234/64", "192.168.20.254/24"],
      getSniffed: () => true,
      getParentInterfaceId: () => null,
    });
    const snapshot = ConfigurationSnapshot.create(
      "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa",
      1,
      SnapshotType.create("auto_save"),
      Checksum.create("0".repeat(64)),
      true,
      {
        bundle: {
          rules: { items: [] },
          zones: { items: [] },
          zone_interfaces: { items: [zoneInterface] },
          zone_pairs: { items: [] },
          nat_rules: { items: [] },
          dns_blacklist: { items: [] },
          ssl_bypass_list: { items: [] },
          ips_signatures: { items: [] },
          ml_model: null,
          firewall_certificates: { items: [] },
          tls_inspection_policy: undefined,
        },
      },
      "test",
      new Date("2026-05-09T00:00:00.000Z"),
      "tester",
    );

    await service.pushActiveConfigSnapshot(snapshot, "apply");

    expect(request.snapshot.bundle.zoneInterfaces[0].addresses).toEqual([
      "192.168.20.254/24",
    ]);
  });

  it("serializes smtp matchers into the gRPC payload", async () => {
    let request: any;
    const client = {
      getService: () => ({
        pushActiveConfigSnapshot: (value: any) => {
          request = value;
          return of({ accepted: true, appliedSnapshotId: value.snapshot.id });
        },
      }),
    } as any;
    const service = new GrpcConfigSnapshotPushService(client);
    service.onModuleInit();

    const rule = methodObject({
      getId: () => "88888888-8888-4888-8888-888888888888",
      getName: () => "SMTP allowlist",
      getZonePairId: () => "33333333-3333-4333-8333-333333333333",
      getPriority: () => Priority.create(10),
      getContent: () => "match protocol { = smtp : verdict allow }",
      getSmtpMatchers: () => ({
        sender: [{ regex: "^.*@trusted\\.com$", onMatch: "allow" }],
        recipient: [{ regex: "^ops@company\\.com$", onMatch: "deny" }],
        message: [],
      }),
    });

    const snapshot = ConfigurationSnapshot.create(
      "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa",
      1,
      SnapshotType.create("auto_save"),
      Checksum.create("0".repeat(64)),
      true,
      {
        bundle: {
          rules: { items: [rule] },
          zones: { items: [] },
          zone_interfaces: { items: [] },
          zone_pairs: { items: [] },
          nat_rules: { items: [] },
          dns_blacklist: { items: [] },
          ssl_bypass_list: { items: [] },
          ips_signatures: { items: [] },
          ml_model: null,
          firewall_certificates: { items: [] },
          tls_inspection_policy: undefined,
        },
      },
      "test",
      new Date("2026-05-09T00:00:00.000Z"),
      "tester",
    );

    await service.pushActiveConfigSnapshot(snapshot, "apply");

    expect(request.snapshot.bundle.rules[0]).toMatchObject({
      id: "88888888-8888-4888-8888-888888888888",
      name: "SMTP allowlist",
      smtpMatchers: {
        sender: [
          {
            regex: "(?s)^.*@trusted\\.com$",
            onMatch: GrpcSmtpMatchAction.SMTP_MATCH_ACTION_ALLOW,
          },
        ],
        recipient: [
          {
            regex: "(?s)^ops@company\\.com$",
            onMatch: GrpcSmtpMatchAction.SMTP_MATCH_ACTION_DENY,
          },
        ],
        message: [],
      },
    });
  });
});
