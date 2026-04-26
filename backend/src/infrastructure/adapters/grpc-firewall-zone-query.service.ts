import { status as GrpcStatus } from "@grpc/grpc-js";
import {
  BadRequestException,
  HttpException,
  Inject,
  Injectable,
  Logger,
  NotFoundException,
  OnModuleInit,
  ServiceUnavailableException,
} from "@nestjs/common";
import type { ClientGrpc } from "@nestjs/microservices";
import { firstValueFrom } from "rxjs";
import type {
  IFirewallZoneQueryService,
  UpdateZoneInterfacePropertiesInput,
} from "../../application/ports/firewall-zone-query-service.interface.js";
import { Zone } from "../../domain/entities/zone.entity.js";
import {
  ZoneInterface,
  type ZoneInterfaceStatus,
} from "../../domain/entities/zone-interface.entity.js";
import {
  ZonePair,
  type ZonePairPolicy,
} from "../../domain/entities/zone-pair.entity.js";
import { DefaultPolicy } from "../grpc/generated/common/common.js";
import {
  type Zone as GrpcZone,
  type ZoneInterface as GrpcZoneInterface,
  type ZonePair as GrpcZonePair,
  InterfaceAdministrativeState,
  InterfaceStatus,
} from "../grpc/generated/config/config_models.js";
import {
  FIREWALL_QUERY_SERVICE_NAME,
  type FirewallQueryServiceClient,
} from "../grpc/generated/services/query_service.js";
import { FIREWALL_QUERY_GRPC_CLIENT_TOKEN } from "./grpc-firewall-dns-inspection-query.service.js";

@Injectable()
export class GrpcFirewallZoneQueryService
  implements IFirewallZoneQueryService, OnModuleInit
{
  private readonly logger = new Logger(GrpcFirewallZoneQueryService.name);
  private firewallQueryClient: FirewallQueryServiceClient;

  constructor(
    @Inject(FIREWALL_QUERY_GRPC_CLIENT_TOKEN)
    private readonly grpcClient: ClientGrpc,
  ) {}

  onModuleInit(): void {
    this.firewallQueryClient =
      this.grpcClient.getService<FirewallQueryServiceClient>(
        FIREWALL_QUERY_SERVICE_NAME,
      );
  }

  async getZones(): Promise<Zone[]> {
    try {
      const response = await firstValueFrom(
        this.firewallQueryClient.getZones({}),
      );

      return response.zones.map((zone) => this.toZoneEntity(zone));
    } catch (error) {
      throw this.toTransportException("get zones", error);
    }
  }

  async getZone(id: string): Promise<Zone | null> {
    try {
      const response = await firstValueFrom(
        this.firewallQueryClient.getZone({ id }),
      );

      return response.zone ? this.toZoneEntity(response.zone) : null;
    } catch (error) {
      throw this.toTransportException("get zone", error);
    }
  }

  async getZoneInterfaces(): Promise<ZoneInterface[]> {
    try {
      const response = await firstValueFrom(
        this.firewallQueryClient.getZoneInterfaces({}),
      );

      return response.zoneInterfaces.map((zoneInterface) =>
        this.toZoneInterfaceEntity(zoneInterface),
      );
    } catch (error) {
      throw this.toTransportException("get zone interfaces", error);
    }
  }

  async getZoneInterface(id: string): Promise<ZoneInterface | null> {
    try {
      const response = await firstValueFrom(
        this.firewallQueryClient.getZoneInterface({ id }),
      );

      return response.zoneInterface
        ? this.toZoneInterfaceEntity(response.zoneInterface)
        : null;
    } catch (error) {
      throw this.toTransportException("get zone interface", error);
    }
  }

  async getLiveZoneInterfaces(): Promise<ZoneInterface[]> {
    try {
      this.logger.log({
        event: "firewall.zone_interfaces.live.get.started",
        message: "loading live zone interfaces from firewall",
      });

      const response = await firstValueFrom(
        this.firewallQueryClient.getLiveZoneInterfaces({}),
      );

      this.logger.log({
        event: "firewall.zone_interfaces.live.get.response",
        message: "loaded live zone interfaces response from firewall",
        response,
        zoneInterfacesType: typeof response?.zoneInterfaces,
        zoneInterfacesCount: response?.zoneInterfaces?.length,
      });

      if (!response?.zoneInterfaces) {
        throw new ServiceUnavailableException(
          "Firewall query service returned empty live zone interfaces response.",
        );
      }

      return response.zoneInterfaces.map((zoneInterface) =>
        this.toZoneInterfaceEntity(zoneInterface),
      );
    } catch (error) {
      this.logger.error(
        {
          event: "firewall.zone_interfaces.live.get.failed",
          message: "failed to load live zone interfaces from firewall",
          error: error instanceof Error ? error.message : "Unknown gRPC error",
          grpcStatusCode: this.getGrpcStatusCode(error),
        },
        error instanceof Error ? error.stack : undefined,
      );

      throw this.toTransportException("get live zone interfaces", error);
    }
  }

  async setInterfaceState(id: string, isActive: boolean): Promise<void> {
    try {
      await firstValueFrom(
        this.firewallQueryClient.setInterfaceState({
          id,
          state: isActive
            ? InterfaceAdministrativeState.INTERFACE_ADMINISTRATIVE_STATE_UP
            : InterfaceAdministrativeState.INTERFACE_ADMINISTRATIVE_STATE_DOWN,
        }),
      );
    } catch (error) {
      throw this.toTransportException("set interface state", error);
    }
  }

  async updateZoneInterfaceProperties(
    input: UpdateZoneInterfacePropertiesInput,
  ): Promise<void> {
    try {
      await firstValueFrom(
        this.firewallQueryClient.updateZoneInterfaceProperties({
          id: input.id,
          interfaceName: input.interfaceName,
          vlanId: input.vlanId,
          address: input.address,
        }),
      );
    } catch (error) {
      throw this.toTransportException(
        "update zone interface properties",
        error,
      );
    }
  }

  async getZonePairs(): Promise<ZonePair[]> {
    try {
      const response = await firstValueFrom(
        this.firewallQueryClient.getZonePairs({}),
      );

      return response.zonePairs.map((zonePair) =>
        this.toZonePairEntity(zonePair),
      );
    } catch (error) {
      throw this.toTransportException("get zone pairs", error);
    }
  }

  async getZonePair(id: string): Promise<ZonePair | null> {
    try {
      const response = await firstValueFrom(
        this.firewallQueryClient.getZonePair({ id }),
      );

      return response.zonePair
        ? this.toZonePairEntity(response.zonePair)
        : null;
    } catch (error) {
      throw this.toTransportException("get zone pair", error);
    }
  }

  private toZoneEntity(zone: GrpcZone): Zone {
    return Zone.create(zone.id, zone.name, null, true, new Date(), "", [
      ...zone.interfaceIds,
    ]);
  }

  private toZoneInterfaceEntity(
    zoneInterface: GrpcZoneInterface,
  ): ZoneInterface {
    return ZoneInterface.create(
      zoneInterface.id,
      zoneInterface.zoneId,
      zoneInterface.interfaceName,
      zoneInterface.vlanId ?? null,
      this.toZoneInterfaceStatus(zoneInterface.status),
      [...zoneInterface.addresses],
      new Date(),
    );
  }

  private toZonePairEntity(zonePair: GrpcZonePair): ZonePair {
    return ZonePair.create(
      zonePair.id,
      zonePair.srcZoneId,
      zonePair.dstZoneId,
      this.toZonePairPolicy(zonePair.defaultPolicy),
      new Date(),
      "",
    );
  }

  private toZoneInterfaceStatus(status: InterfaceStatus): ZoneInterfaceStatus {
    switch (status) {
      case InterfaceStatus.INTERFACE_STATUS_ACTIVE:
        return "active";
      case InterfaceStatus.INTERFACE_STATUS_INACTIVE:
        return "inactive";
      case InterfaceStatus.INTERFACE_STATUS_MISSING:
        return "missing";
      case InterfaceStatus.INTERFACE_STATUS_UNKNOWN:
      case InterfaceStatus.UNRECOGNIZED:
        return "unknown";
      case InterfaceStatus.INTERFACE_STATUS_UNSPECIFIED:
      default:
        return "unspecified";
    }
  }

  private toZonePairPolicy(defaultPolicy: DefaultPolicy): ZonePairPolicy {
    switch (defaultPolicy) {
      case DefaultPolicy.DEFAULT_POLICY_ALLOW:
        return "ALLOW";
      case DefaultPolicy.DEFAULT_POLICY_DROP:
        return "DROP";
      case DefaultPolicy.DEFAULT_POLICY_UNSPECIFIED:
      case DefaultPolicy.UNRECOGNIZED:
      default:
        return "UNSPECIFIED";
    }
  }

  private toTransportException(action: string, error: unknown): HttpException {
    if (error instanceof HttpException) {
      return error;
    }

    const reason =
      error instanceof Error ? error.message : "Unknown gRPC error";

    switch (this.getGrpcStatusCode(error)) {
      case GrpcStatus.INVALID_ARGUMENT:
        return new BadRequestException(
          `Firewall query service failed to ${action}. ${reason}`,
        );
      case GrpcStatus.NOT_FOUND:
        return new NotFoundException(
          `Firewall query service failed to ${action}. ${reason}`,
        );
      default:
        return new ServiceUnavailableException(
          `Firewall query service failed to ${action}. ${reason}`,
        );
    }
  }

  private getGrpcStatusCode(error: unknown): number | undefined {
    if (typeof error !== "object" || error === null || !("code" in error)) {
      return undefined;
    }

    const code = (error as { code: unknown }).code;
    return typeof code === "number" ? code : undefined;
  }
}
