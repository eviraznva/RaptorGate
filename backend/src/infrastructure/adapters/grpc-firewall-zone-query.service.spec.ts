import { status as GrpcStatus } from "@grpc/grpc-js";
import { beforeEach, describe, expect, it, jest } from "@jest/globals";
import {
  BadRequestException,
  NotFoundException,
  ServiceUnavailableException,
} from "@nestjs/common";
import type { ClientGrpc } from "@nestjs/microservices";
import { of, throwError } from "rxjs";
import { DefaultPolicy } from "../grpc/generated/common/common.js";
import { InterfaceStatus } from "../grpc/generated/config/config_models.js";
import { ZoneJsonMapper } from "../persistence/mappers/zone-json.mapper.js";
import { GrpcFirewallZoneQueryService } from "./grpc-firewall-zone-query.service.js";

const createClient = () => ({
  getZones: jest.fn(),
  getZone: jest.fn(),
  getZoneInterfaces: jest.fn(),
  getZoneInterface: jest.fn(),
  getLiveZoneInterfaces: jest.fn(),
  getZonePairs: jest.fn(),
  getZonePair: jest.fn(),
});

describe("GrpcFirewallZoneQueryService", () => {
  let client: ReturnType<typeof createClient>;
  let service: GrpcFirewallZoneQueryService;

  beforeEach(() => {
    client = createClient();

    const grpcClient = {
      getService: jest.fn().mockReturnValue(client),
    } as unknown as ClientGrpc;

    service = new GrpcFirewallZoneQueryService(grpcClient);
    service.onModuleInit();
  });

  it("calls getZones and maps zones to domain entities", async () => {
    client.getZones.mockReturnValue(
      of({
        zones: [
          {
            id: "zone-1",
            name: "inside",
            interfaceIds: ["if-1", "if-2"],
          },
        ],
      }),
    );

    const zones = await service.getZones();

    expect(client.getZones).toHaveBeenCalledWith({});
    expect(zones).toHaveLength(1);
    expect(zones[0].getId()).toBe("zone-1");
    expect(zones[0].getName()).toBe("inside");
    expect(zones[0].getDescription()).toBeNull();
    expect(zones[0].getIsActive()).toBe(true);
    expect(zones[0].getCreatedBy()).toBe("");
    expect(zones[0].getCreatedAt()).toBeInstanceOf(Date);
    expect(zones[0].getInterfaceIds()).toEqual(["if-1", "if-2"]);
  });

  it("calls getZone and maps a single zone", async () => {
    client.getZone.mockReturnValue(
      of({
        zone: {
          id: "zone-2",
          name: "dmz",
          interfaceIds: ["if-3"],
        },
      }),
    );

    const zone = await service.getZone("zone-2");

    expect(client.getZone).toHaveBeenCalledWith({ id: "zone-2" });
    expect(zone?.getId()).toBe("zone-2");
    expect(zone?.getInterfaceIds()).toEqual(["if-3"]);
  });

  it("calls getZoneInterfaces and maps interface fields", async () => {
    client.getZoneInterfaces.mockReturnValue(
      of({
        zoneInterfaces: [
          {
            id: "zi-1",
            zoneId: "zone-1",
            interfaceName: "eth0",
            status: InterfaceStatus.INTERFACE_STATUS_UNSPECIFIED,
            addresses: ["192.168.50.10/24"],
          },
          {
            id: "zi-2",
            zoneId: "zone-1",
            interfaceName: "eth1",
            vlanId: 20,
            status: InterfaceStatus.INTERFACE_STATUS_ACTIVE,
            addresses: ["2001:db8::1/64"],
          },
          {
            id: "zi-3",
            zoneId: "zone-2",
            interfaceName: "eth2",
            status: InterfaceStatus.INTERFACE_STATUS_INACTIVE,
            addresses: [],
          },
          {
            id: "zi-4",
            zoneId: "zone-2",
            interfaceName: "eth3",
            status: InterfaceStatus.INTERFACE_STATUS_MISSING,
            addresses: [],
          },
          {
            id: "zi-5",
            zoneId: "zone-3",
            interfaceName: "eth4",
            status: InterfaceStatus.INTERFACE_STATUS_UNKNOWN,
            addresses: [],
          },
        ],
      }),
    );

    const zoneInterfaces = await service.getZoneInterfaces();

    expect(client.getZoneInterfaces).toHaveBeenCalledWith({});
    expect(
      zoneInterfaces.map((zoneInterface) => zoneInterface.getStatus()),
    ).toEqual(["unspecified", "active", "inactive", "missing", "unknown"]);
    expect(zoneInterfaces[0].getVlanId()).toBeNull();
    expect(zoneInterfaces[1].getVlanId()).toBe(20);
    expect(zoneInterfaces[0].getAddresses()).toEqual(["192.168.50.10/24"]);
    expect(zoneInterfaces[1].getAddresses()).toEqual(["2001:db8::1/64"]);
  });

  it("calls getZoneInterface and maps a single interface", async () => {
    client.getZoneInterface.mockReturnValue(
      of({
        zoneInterface: {
          id: "zi-1",
          zoneId: "zone-1",
          interfaceName: "eth0",
          vlanId: 10,
          status: InterfaceStatus.INTERFACE_STATUS_ACTIVE,
          addresses: ["10.0.0.1/24"],
        },
      }),
    );

    const zoneInterface = await service.getZoneInterface("zi-1");

    expect(client.getZoneInterface).toHaveBeenCalledWith({ id: "zi-1" });
    expect(zoneInterface?.getId()).toBe("zi-1");
    expect(zoneInterface?.getVlanId()).toBe(10);
    expect(zoneInterface?.getAddresses()).toEqual(["10.0.0.1/24"]);
  });

  it("calls getLiveZoneInterfaces and maps live interfaces", async () => {
    client.getLiveZoneInterfaces.mockReturnValue(
      of({
        zoneInterfaces: [
          {
            id: "live-1",
            zoneId: "zone-1",
            interfaceName: "eth9",
            status: InterfaceStatus.INTERFACE_STATUS_ACTIVE,
            addresses: ["172.16.0.1/16"],
          },
        ],
      }),
    );

    const zoneInterfaces = await service.getLiveZoneInterfaces();

    expect(client.getLiveZoneInterfaces).toHaveBeenCalledWith({});
    expect(zoneInterfaces[0].getId()).toBe("live-1");
    expect(zoneInterfaces[0].getStatus()).toBe("active");
  });

  it("calls getZonePairs and maps default policies", async () => {
    client.getZonePairs.mockReturnValue(
      of({
        zonePairs: [
          {
            id: "zp-1",
            srcZoneId: "zone-1",
            dstZoneId: "zone-2",
            defaultPolicy: DefaultPolicy.DEFAULT_POLICY_UNSPECIFIED,
          },
          {
            id: "zp-2",
            srcZoneId: "zone-2",
            dstZoneId: "zone-3",
            defaultPolicy: DefaultPolicy.DEFAULT_POLICY_ALLOW,
          },
          {
            id: "zp-3",
            srcZoneId: "zone-3",
            dstZoneId: "zone-4",
            defaultPolicy: DefaultPolicy.DEFAULT_POLICY_DROP,
          },
        ],
      }),
    );

    const zonePairs = await service.getZonePairs();

    expect(client.getZonePairs).toHaveBeenCalledWith({});
    expect(zonePairs.map((zonePair) => zonePair.getDefaultPolicy())).toEqual([
      "UNSPECIFIED",
      "ALLOW",
      "DROP",
    ]);
  });

  it("calls getZonePair and maps a single zone pair", async () => {
    client.getZonePair.mockReturnValue(
      of({
        zonePair: {
          id: "zp-1",
          srcZoneId: "zone-1",
          dstZoneId: "zone-2",
          defaultPolicy: DefaultPolicy.DEFAULT_POLICY_DROP,
        },
      }),
    );

    const zonePair = await service.getZonePair("zp-1");

    expect(client.getZonePair).toHaveBeenCalledWith({ id: "zp-1" });
    expect(zonePair?.getId()).toBe("zp-1");
    expect(zonePair?.getDefaultPolicy()).toBe("DROP");
  });

  it("returns null for empty single-resource responses", async () => {
    client.getZone.mockReturnValue(of({}));
    client.getZoneInterface.mockReturnValue(of({}));
    client.getZonePair.mockReturnValue(of({}));

    await expect(service.getZone("missing-zone")).resolves.toBeNull();
    await expect(
      service.getZoneInterface("missing-interface"),
    ).resolves.toBeNull();
    await expect(service.getZonePair("missing-pair")).resolves.toBeNull();
  });

  it("maps INVALID_ARGUMENT to BadRequestException", async () => {
    client.getZone.mockReturnValue(
      throwError(() =>
        Object.assign(new Error("invalid id"), {
          code: GrpcStatus.INVALID_ARGUMENT,
        }),
      ),
    );

    await expect(service.getZone("bad-id")).rejects.toBeInstanceOf(
      BadRequestException,
    );
  });

  it("maps NOT_FOUND to NotFoundException", async () => {
    client.getZone.mockReturnValue(
      throwError(() =>
        Object.assign(new Error("zone not found"), {
          code: GrpcStatus.NOT_FOUND,
        }),
      ),
    );

    await expect(service.getZone("missing-zone")).rejects.toBeInstanceOf(
      NotFoundException,
    );
  });

  it("maps other gRPC errors to ServiceUnavailableException", async () => {
    client.getZone.mockReturnValue(
      throwError(() =>
        Object.assign(new Error("unavailable"), {
          code: GrpcStatus.UNAVAILABLE,
        }),
      ),
    );

    await expect(service.getZone("zone-1")).rejects.toBeInstanceOf(
      ServiceUnavailableException,
    );
  });

  it("keeps existing JSON zone records compatible with default interfaceIds", () => {
    const zone = ZoneJsonMapper.toDomain({
      id: "5d375e76-b212-4c9e-8da0-601e5ebb3cd3",
      name: "inside",
      description: null,
      isActive: true,
      createdAt: "2026-03-20T23:11:43.970Z",
      createdBy: "77144f8f-c7b8-4ff4-988f-700f8cd3f937",
    });

    expect(zone.getInterfaceIds()).toEqual([]);
  });
});
