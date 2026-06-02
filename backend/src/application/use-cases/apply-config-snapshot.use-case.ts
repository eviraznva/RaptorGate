import { hash } from "node:crypto";
import { Inject, Injectable, Logger } from "@nestjs/common";
import { ConfigurationSnapshot } from "../../domain/entities/configuration-snapshot.entity.js";
import { AccessTokenIsInvalidException } from "../../domain/exceptions/acces-token-is-invalid.exception.js";
import type { IConfigSnapshotRepository } from "../../domain/repositories/config-snapshot.repository.js";
import { CONFIG_SNAPSHOT_REPOSITORY_TOKEN } from "../../domain/repositories/config-snapshot.repository.js";
import type { IDnsInspectionRepository } from "../../domain/repositories/dns-inspection.repository.js";
import { DNS_INSPECTION_REPOSITORY_TOKEN } from "../../domain/repositories/dns-inspection.repository.js";
import type { IFirewallCertificateRepository } from "../../domain/repositories/firewall-certificate.repository.js";
import { FIREWALL_CERTIFICATE_REPOSITORY_TOKEN } from "../../domain/repositories/firewall-certificate.repository.js";
import {
  IDENTITY_CONFIG_REPOSITORY_TOKEN,
  type IIdentityConfigRepository,
} from "../../domain/repositories/identity-config.repository.js";
import type { IIpsConfigRepository } from "../../domain/repositories/ips-config.repository.js";
import { IPS_CONFIG_REPOSITORY_TOKEN } from "../../domain/repositories/ips-config.repository.js";
import type { INatRulesRepository } from "../../domain/repositories/nat-rules.repository.js";
import { NAT_RULES_REPOSITORY_TOKEN } from "../../domain/repositories/nat-rules.repository.js";
import type { IPermissionRepository } from "../../domain/repositories/permission.repository.js";
import { PERMISSION_REPOSITORY_TOKEN } from "../../domain/repositories/permission.repository.js";
import type { IRoleRepository } from "../../domain/repositories/role.repository.js";
import { ROLE_REPOSITORY_TOKEN } from "../../domain/repositories/role.repository.js";
import type { IRolePermissionsRepository } from "../../domain/repositories/role-permissions.repository.js";
import { ROLE_PERMISSIONS_REPOSITORY_TOKEN } from "../../domain/repositories/role-permissions.repository.js";
import type { IRulesRepository } from "../../domain/repositories/rules-repository.js";
import { RULES_REPOSITORY_TOKEN } from "../../domain/repositories/rules-repository.js";
import type { ISslBypassRepository } from "../../domain/repositories/ssl-bypass.repository.js";
import { SSL_BYPASS_REPOSITORY_TOKEN } from "../../domain/repositories/ssl-bypass.repository.js";
import type { IUserRepository } from "../../domain/repositories/user.repository.js";
import { USER_REPOSITORY_TOKEN } from "../../domain/repositories/user.repository.js";
import type { IUserRolesRepository } from "../../domain/repositories/user-roles.repository.js";
import { USER_ROLES_REPOSITORY_TOKEN } from "../../domain/repositories/user-roles.repository.js";
import type { IZoneRepository } from "../../domain/repositories/zone.repository.js";
import { ZONE_REPOSITORY_TOKEN } from "../../domain/repositories/zone.repository.js";
import type { IZoneInterfaceRepository } from "../../domain/repositories/zone-interface.repository.js";
import { ZONE_INTERFACE_REPOSITORY_TOKEN } from "../../domain/repositories/zone-interface.repository.js";
import type { IZonePairRepository } from "../../domain/repositories/zone-pair.repository.js";
import { ZONE_PAIR_REPOSITORY_TOKEN } from "../../domain/repositories/zone-pair.repository.js";
import { Checksum } from "../../domain/value-objects/checksum.vo.js";
import {
  type ConfigSnapshotPayload,
  normalizeTlsInspectionPolicy,
} from "../../domain/value-objects/config-snapshot-payload.interface.js";
import { SnapshotType } from "../../domain/value-objects/snapshot-type.vo.js";
import { IdentityConfigJsonMapper } from "../../infrastructure/persistence/mappers/identity-config-json.mapper.js";
import type { ApplyConfigSnapshotDto } from "../dtos/apply-config-snapshot.dto.js";
import type { ApplyConfigSnapshotResponseDto } from "../dtos/apply-config-snapshot-response.dto.js";
import type { IConfigSnapshotPushService } from "../ports/config-snapshot-push-service.interface.js";
import { CONFIG_SNAPSHOT_PUSH_SERVICE_TOKEN } from "../ports/config-snapshot-push-service.interface.js";
import type { IFirewallZoneQueryService } from "../ports/firewall-zone-query-service.interface.js";
import { FIREWALL_ZONE_QUERY_SERVICE_TOKEN } from "../ports/firewall-zone-query-service.interface.js";
import { normalizeZoneInterfaceForConfig } from "../services/zone-interface-config-normalizer.js";
import type { ITokenService } from "../ports/token-service.interface.js";
import { TOKEN_SERVICE_TOKEN } from "../ports/token-service.interface.js";
import { IdentitySecretReferenceValidatorService } from "../services/identity-secret-reference-validator.service.js";

@Injectable()
export class ApplyConfigSnapshotUseCase {
  private readonly logger = new Logger(ApplyConfigSnapshotUseCase.name);

  constructor(
    @Inject(CONFIG_SNAPSHOT_REPOSITORY_TOKEN)
    private readonly configSnapshotRepository: IConfigSnapshotRepository,
    @Inject(IPS_CONFIG_REPOSITORY_TOKEN)
    private readonly ipsConfigRepository: IIpsConfigRepository,
    @Inject(NAT_RULES_REPOSITORY_TOKEN)
    private readonly natRulesRepository: INatRulesRepository,
    @Inject(PERMISSION_REPOSITORY_TOKEN)
    private readonly permissionRepository: IPermissionRepository,
    @Inject(ROLE_REPOSITORY_TOKEN)
    private readonly roleRepository: IRoleRepository,
    @Inject(RULES_REPOSITORY_TOKEN)
    private readonly rulesRepository: IRulesRepository,
    @Inject(USER_REPOSITORY_TOKEN)
    private readonly userRepository: IUserRepository,
    @Inject(ZONE_PAIR_REPOSITORY_TOKEN)
    private readonly zonePairRepository: IZonePairRepository,
    @Inject(ZONE_REPOSITORY_TOKEN)
    private readonly zoneRepository: IZoneRepository,
    @Inject(ZONE_INTERFACE_REPOSITORY_TOKEN)
    private readonly zoneInterfaceRepository: IZoneInterfaceRepository,
    @Inject(TOKEN_SERVICE_TOKEN) private readonly tokenService: ITokenService,
    @Inject(ROLE_PERMISSIONS_REPOSITORY_TOKEN)
    private readonly rolePermissionsRepository: IRolePermissionsRepository,
    @Inject(USER_ROLES_REPOSITORY_TOKEN)
    private readonly userRolesRepository: IUserRolesRepository,
    @Inject(CONFIG_SNAPSHOT_PUSH_SERVICE_TOKEN)
    private readonly configSnapshotPushService: IConfigSnapshotPushService,
    @Inject(FIREWALL_CERTIFICATE_REPOSITORY_TOKEN)
    private readonly firewallCertificateRepository: IFirewallCertificateRepository,
    @Inject(SSL_BYPASS_REPOSITORY_TOKEN)
    private readonly sslBypassRepository: ISslBypassRepository,
    @Inject(IDENTITY_CONFIG_REPOSITORY_TOKEN)
    private readonly identityConfigRepository: IIdentityConfigRepository,
    private readonly identitySecretReferenceValidator: IdentitySecretReferenceValidatorService,
    @Inject(DNS_INSPECTION_REPOSITORY_TOKEN)
    private readonly dnsInspectionRepository: IDnsInspectionRepository,
    @Inject(FIREWALL_ZONE_QUERY_SERVICE_TOKEN)
    private readonly firewallZoneQueryService: IFirewallZoneQueryService,
  ) {}

  async execute(
    dto: ApplyConfigSnapshotDto,
  ): Promise<ApplyConfigSnapshotResponseDto> {
    const claims = this.tokenService.decodeAccessToken(dto.accessToken);
    if (!claims) throw new AccessTokenIsInvalidException();

    const allNatRules = await this.natRulesRepository.findAll();
    const ipsConfig = await this.ipsConfigRepository.get();
    const allRules = await this.rulesRepository.findAll();
    const allUsers = await this.userRepository.findAll();
    const allZones = await this.zoneRepository.findAll();
    const allZoneInterfaces = await this.resolveZoneInterfaces();
    const allZonePairs = await this.zonePairRepository.findAll();
    const allCerts = await this.firewallCertificateRepository.findAll();
    const allBypass = await this.sslBypassRepository.findAll();
    const identityConfig = await this.identityConfigRepository.find();
    if (dto.isActive) {
      await this.identitySecretReferenceValidator.validateActiveConfig(
        identityConfig,
      );
    }
    const dnsInspectionConfig = await this.dnsInspectionRepository.get();
    const allConfigSnapshots =
      await this.configSnapshotRepository.findAllSnapshots();
    const currentActiveSnapshot = allConfigSnapshots.find((snapshot) =>
      snapshot.getIsActive(),
    );
    const tlsInspectionPolicy = this.resolveTlsInspectionPolicy(
      currentActiveSnapshot?.deserializePayload(),
    );

    // const rolePermissions = await this.rolePermissionsRepository.findAll();
    // const userRoles = await this.userRolesRepository.findAll();

    const configSnposhotPayload = {
      bundle: {
        rules: {
          items: [...allRules],
        },
        zones: {
          items: [...allZones],
        },
        zone_interfaces: {
          items: [...allZoneInterfaces],
        },
        zone_pairs: {
          items: [...allZonePairs],
        },
        nat_rules: {
          items: [...allNatRules],
        },
        dns_blacklist: {
          items: [], // TODO: implement dns blacklist repository and add to snapshot
        },
        ssl_bypass_list: {
          items: [...allBypass],
        },
        ips_signatures: {
          items: [], // TODO: implement ips signatures repository and add to snapshot
        },
        ips_config: ipsConfig,
        ml_model: null,
        firewall_certificates: {
          items: [...allCerts],
        },
        tls_inspection_policy: tlsInspectionPolicy,
        identity_config: IdentityConfigJsonMapper.toPayload(identityConfig),
        dns_inspection_config: dnsInspectionConfig,
        users: {
          items: [...allUsers],
        },
        // roles: {
        //   items: [...allRoles],
        // },
        // permissions: {
        //   items: [...allPermisions],
        // },
        // role_permissions: {
        //   items: [...rolePermissions],
        // },
        // user_roles: {
        //   items: [...userRoles],
        // },
      },
    };

    const highestVersionNumber = allConfigSnapshots.reduce((prev, curr) => {
      if (curr.getVersionNumber() > prev) return curr.getVersionNumber();
    }, 0);

    const checksum = hash("sha256", JSON.stringify(configSnposhotPayload));
    const newConfigSnapshot = ConfigurationSnapshot.create(
      crypto.randomUUID(),
      highestVersionNumber !== undefined ? highestVersionNumber + 1 : 1,
      SnapshotType.create(dto.snapshotType),
      Checksum.create(checksum),
      dto.isActive,
      configSnposhotPayload,
      dto.changeSummary,
      new Date(),
      claims.sub,
    );

    await this.configSnapshotRepository.save(newConfigSnapshot);

    if (currentActiveSnapshot && dto.isActive) {
      currentActiveSnapshot.setIsActive(false);
      await this.configSnapshotRepository.save(currentActiveSnapshot);
    }

    if (dto.isActive) {
      await this.configSnapshotPushService.pushActiveConfigSnapshot(
        newConfigSnapshot,
        "apply",
      );
    }

    this.logger.log({
      event: "config_snapshot.apply.succeeded",
      message: "configuration snapshot applied",
      actorId: claims.sub,
      snapshotId: newConfigSnapshot.getId(),
      versionNumber: newConfigSnapshot.getVersionNumber(),
      checksum,
      isActive: dto.isActive,
      counts: {
        rules: allRules.length,
        zones: allZones.length,
        zoneInterfaces: allZoneInterfaces.length,
        zonePairs: allZonePairs.length,
        natRules: allNatRules.length,
        users: allUsers.length,
      },
    });

    return {
      id: newConfigSnapshot.getId(),
      versionNumber: newConfigSnapshot.getVersionNumber(),
      snapshotType: newConfigSnapshot.getSnapshotType().getValue(),
      checksum: newConfigSnapshot.getChecksum().getValue(),
      isActive: newConfigSnapshot.getIsActive(),
      payloadJson: newConfigSnapshot.getPayloadJson(),
      changesSummary: newConfigSnapshot.getChangesSummary(),
      createdAt: newConfigSnapshot.getCreatedAt(),
      createdBy: newConfigSnapshot.getCreatedBy(),
    };
  }

  private async resolveZoneInterfaces() {
    const saved = await this.zoneInterfaceRepository.findAll();
    if (saved.length > 0) return saved;

    this.logger.warn({
      event: "config_snapshot.zone_interfaces.sync",
      message:
        "no zone interfaces in backend, fetching live state from firewall",
    });

    const live = (
      await this.firewallZoneQueryService.getLiveZoneInterfaces()
    ).map((zoneInterface) => normalizeZoneInterfaceForConfig(zoneInterface));
    if (live.length > 0) {
      await this.zoneInterfaceRepository.overwriteAll(live);
    }
    return live;
  }

  private resolveTlsInspectionPolicy(payload?: ConfigSnapshotPayload) {
    return normalizeTlsInspectionPolicy(payload?.bundle.tls_inspection_policy);
  }
}
