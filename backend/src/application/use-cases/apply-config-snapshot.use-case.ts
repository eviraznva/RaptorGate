import { ROLE_PERMISSIONS_REPOSITORY_TOKEN } from '../../domain/repositories/role-permissions.repository.js';
import { AccessTokenIsInvalidException } from '../../domain/exceptions/acces-token-is-invalid.exception.js';
import { CONFIG_SNAPSHOT_REPOSITORY_TOKEN } from '../../domain/repositories/config-snapshot.repository.js';
import type { IRolePermissionsRepository } from '../../domain/repositories/role-permissions.repository.js';
import type { IConfigSnapshotRepository } from '../../domain/repositories/config-snapshot.repository.js';
import { PERMISSION_REPOSITORY_TOKEN } from '../../domain/repositories/permission.repository.js';
import { USER_ROLES_REPOSITORY_TOKEN } from '../../domain/repositories/user-roles.repository.js';
import type { IPermissionRepository } from '../../domain/repositories/permission.repository.js';
import { ConfigurationSnapshot } from '../../domain/entities/configuration-snapshot.entity.js';
import { NAT_RULES_REPOSITORY_TOKEN } from '../../domain/repositories/nat-rules.repository.js';
import { ZONE_PAIR_REPOSITORY_TOKEN } from '../../domain/repositories/zone-pair.repository.js';
import type { IUserRolesRepository } from '../../domain/repositories/user-roles.repository.js';
import type { INatRulesRepository } from '../../domain/repositories/nat-rules.repository.js';
import type { IZonePairRepository } from '../../domain/repositories/zone-pair.repository.js';
import { RULES_REPOSITORY_TOKEN } from '../../domain/repositories/rules-repository.js';
import type { IRulesRepository } from '../../domain/repositories/rules-repository.js';
import { ROLE_REPOSITORY_TOKEN } from '../../domain/repositories/role.repository.js';
import { USER_REPOSITORY_TOKEN } from '../../domain/repositories/user.repository.js';
import { ZONE_REPOSITORY_TOKEN } from '../../domain/repositories/zone.repository.js';
import type { IRoleRepository } from '../../domain/repositories/role.repository.js';
import type { IUserRepository } from '../../domain/repositories/user.repository.js';
import type { IZoneRepository } from '../../domain/repositories/zone.repository.js';
import { ApplyConfigSnapshotDto } from '../dtos/apply-config-snapshot.dto.js';
import { SnapshotType } from '../../domain/value-objects/snapshot-type.vo.js';
import { TOKEN_SERVICE_TOKEN } from '../ports/token-service.interface.js';
import type { ITokenService } from '../ports/token-service.interface.js';
import { Checksum } from '../../domain/value-objects/checksum.vo.js';
import { Inject, Injectable } from '@nestjs/common';
import { hash } from 'node:crypto';

@Injectable()
export class ApplyConfigSnapshotUseCase {
  constructor(
    @Inject(CONFIG_SNAPSHOT_REPOSITORY_TOKEN)
    private readonly configSnapshotRepository: IConfigSnapshotRepository,
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
    @Inject(TOKEN_SERVICE_TOKEN) private readonly tokenService: ITokenService,
    @Inject(ROLE_PERMISSIONS_REPOSITORY_TOKEN)
    private readonly rolePermissionsRepository: IRolePermissionsRepository,
    @Inject(USER_ROLES_REPOSITORY_TOKEN)
    private readonly userRolesRepository: IUserRolesRepository,
  ) {}

  async execute(dto: ApplyConfigSnapshotDto): Promise<void> {
    const claims = this.tokenService.decodeAccessToken(dto.accessToken);
    if (!claims) throw new AccessTokenIsInvalidException();

    const activeNatRules = await this.natRulesRepository.findActive();
    // const allRoles = await this.roleRepository.findAll();
    // const allPermisions = await this.permissionRepository.findAll();
    const activeRules = await this.rulesRepository.findActive();
    const allUsers = await this.userRepository.findAll();
    const activeZones = await this.zoneRepository.findActive();
    const allZonePairs = await this.zonePairRepository.findAll();
    // const rolePermissions = await this.rolePermissionsRepository.findAll();
    // const userRoles = await this.userRolesRepository.findAll();

    const configSnposhotPayload = {
      bundle: {
        rules: {
          items: [...activeRules],
        },
        zones: {
          items: [...activeZones],
        },
        zone_interfaces: {
          items: [], // TODO: implement zone interfaces repository and add to snapshot
        },
        zone_pairs: {
          items: [...allZonePairs],
        },
        nat_rules: {
          items: [...activeNatRules],
        },
        dns_blacklist: {
          items: [], // TODO: implement dns blacklist repository and add to snapshot
        },
        ssl_bypass_list: {
          items: [], // TODO: implement ssl bypass list repository and add to snapshot
        },
        ips_signatures: {
          items: [], // TODO: implement ips signatures repository and add to snapshot
        },
        ml_model: null,
        firewall_certificates: {
          items: [], // TODO: implement firewall certificates repository and add to snapshot
        },
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

    const allConfigSnapshots =
      await this.configSnapshotRepository.findAllSnapshots();

    const highestVersionNumber = allConfigSnapshots.reduce((prev, curr) => {
      if (curr.getVersionNumber() > prev) return curr.getVersionNumber();
    }, 0);

    const checksum = hash('sha256', JSON.stringify(configSnposhotPayload));

    const currentActiveSnapshot = allConfigSnapshots.find((snapshot) =>
      snapshot.getIsActive(),
    );

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
  }
}
