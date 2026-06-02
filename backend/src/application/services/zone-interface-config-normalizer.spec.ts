import { describe, expect, it } from "@jest/globals";
import { ZoneInterface } from "../../domain/entities/zone-interface.entity.js";
import {
  normalizeZoneInterfaceAddressesForConfig,
  normalizeZoneInterfaceForConfig,
} from "./zone-interface-config-normalizer.js";

describe("zone-interface-config-normalizer", () => {
  it("keeps only the preferred desired address for physical interfaces", () => {
    expect(
      normalizeZoneInterfaceAddressesForConfig(null, [
        "fe80::1234/64",
        "2001:db8::10/64",
        "192.168.20.254/24",
      ]),
    ).toEqual(["192.168.20.254/24"]);
  });

  it("preserves all desired addresses for VLAN interfaces", () => {
    expect(
      normalizeZoneInterfaceAddressesForConfig(20, [
        "192.168.20.254/24",
        "2001:db8::20/64",
      ]),
    ).toEqual(["192.168.20.254/24", "2001:db8::20/64"]);
  });

  it("normalizes live physical entities before persisting config", () => {
    const zoneInterface = ZoneInterface.create(
      "55555555-5555-4555-8555-555555555555",
      "11111111-1111-4111-8111-111111111111",
      "eth2",
      null,
      "active",
      ["fe80::1234/64", "10.10.10.1/24"],
      new Date("2026-05-24T00:00:00.000Z"),
      true,
    );

    expect(normalizeZoneInterfaceForConfig(zoneInterface).getAddresses()).toEqual(
      ["10.10.10.1/24"],
    );
  });
});
