import { ROLE_PERMISSIONS_REPOSITORY_TOKEN } from 'src/domain/repositories/role-permissions.repository';
import { AccessTokenIsInvalidException } from 'src/domain/exceptions/acces-token-is-invalid.exception';
import type { IRolePermissionsRepository } from 'src/domain/repositories/role-permissions.repository';
import { CONFIG_SNAPSHOT_REPOSITORY_TOKEN } from 'src/domain/repositories/config-snapshot.repository';
import type { IConfigSnapshotRepository } from 'src/domain/repositories/config-snapshot.repository';
import { USER_ROLES_REPOSITORY_TOKEN } from 'src/domain/repositories/user-roles.repository';
import { PERMISSION_REPOSITORY_TOKEN } from 'src/domain/repositories/permission.repository';
import type { IPermissionRepository } from 'src/domain/repositories/permission.repository';
import { ZONE_PAIR_REPOSITORY_TOKEN } from 'src/domain/repositories/zone-pair.repository';
import { NAT_RULES_REPOSITORY_TOKEN } from 'src/domain/repositories/nat-rules.repository';
import { ConfigurationSnapshot } from 'src/domain/entities/configuration-snapshot.entity';
import type { IUserRolesRepository } from 'src/domain/repositories/user-roles.repository';
import type { IZonePairRepository } from 'src/domain/repositories/zone-pair.repository';
import type { INatRulesRepository } from 'src/domain/repositories/nat-rules.repository';
import { RULES_REPOSITORY_TOKEN } from 'src/domain/repositories/rules-repository';
import type { IRulesRepository } from 'src/domain/repositories/rules-repository';
import { USER_REPOSITORY_TOKEN } from 'src/domain/repositories/user.repository';
import { ZONE_REPOSITORY_TOKEN } from 'src/domain/repositories/zone.repository';
import { ROLE_REPOSITORY_TOKEN } from 'src/domain/repositories/role.repository';
import type { IRoleRepository } from 'src/domain/repositories/role.repository';
import type { IUserRepository } from 'src/domain/repositories/user.repository';
import type { IZoneRepository } from 'src/domain/repositories/zone.repository';
import { ApplyConfigSnapshotDto } from '../dtos/apply-config-snapshot.dto';
import { SnapshotType } from 'src/domain/value-objects/snapshot-type.vo';
import { TOKEN_SERVICE_TOKEN } from '../ports/token-service.interface';
import type { ITokenService } from '../ports/token-service.interface';
import { Checksum } from 'src/domain/value-objects/checksum.vo';
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
    const allPermisions = await this.permissionRepository.findAll();
    const allRoles = await this.roleRepository.findAll();
    const activeRules = await this.rulesRepository.findActive();
    const allUsers = await this.userRepository.findAll();
    const activeZones = await this.zoneRepository.findActive();
    const allZonePairs = await this.zonePairRepository.findAll();
    const rolePermissions = await this.rolePermissionsRepository.findAll();
    const userRoles = await this.userRolesRepository.findAll();

    const configSnposhotPayload = {
      bundle: {
        rules: {
          items: [...activeRules],
        },
        zones: {
          items: [...activeZones],
        },
        zonePairs: {
          items: [...allZonePairs],
        },
        natRules: {
          items: [...activeNatRules],
        },
        uesrs: {
          items: [...allUsers],
        },
        roles: {
          items: [...allRoles],
        },
        permissions: {
          items: [...allPermisions],
        },
        rolePermissions: {
          items: [...rolePermissions],
        },
        userRoles: {
          imtems: [...userRoles],
        },
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
      JSON.stringify(configSnposhotPayload),
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
