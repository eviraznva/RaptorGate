import { JsonRolePermissionsRepository } from 'src/infrastructure/persistence/repositories/json-role-permissions.repository';
import { JsonConfigSnapshotRepository } from 'src/infrastructure/persistence/repositories/json-config-snapshot.repository';
import { JsonPermissionRepository } from 'src/infrastructure/persistence/repositories/json-permission.repository';
import { JsonUserRoleRepository } from 'src/infrastructure/persistence/repositories/json-user-role.repository';
import { JsonZonePairRepository } from 'src/infrastructure/persistence/repositories/json-zone-pair.repository';
import { JsonNatRuleRepository } from 'src/infrastructure/persistence/repositories/json-nat-rule.repository';
import { ROLE_PERMISSIONS_REPOSITORY_TOKEN } from 'src/domain/repositories/role-permissions.repository';
import { ApplyConfigSnapshotUseCase } from 'src/application/use-cases/apply-config-snapshot.use-case';
import { CONFIG_SNAPSHOT_REPOSITORY_TOKEN } from 'src/domain/repositories/config-snapshot.repository';
import { JsonRuleRepository } from 'src/infrastructure/persistence/repositories/json-rule.repository';
import { JsonRoleRepository } from 'src/infrastructure/persistence/repositories/json-role.repository';
import { JsonUserRepository } from 'src/infrastructure/persistence/repositories/json-user.repository';
import { JsonZoneRepository } from 'src/infrastructure/persistence/repositories/json-zone.repository';
import { GetConfigHistoryUseCase } from 'src/application/use-cases/get-config-history.use-case';
import { USER_ROLES_REPOSITORY_TOKEN } from 'src/domain/repositories/user-roles.repository';
import { PERMISSION_REPOSITORY_TOKEN } from 'src/domain/repositories/permission.repository';
import { ZONE_PAIR_REPOSITORY_TOKEN } from 'src/domain/repositories/zone-pair.repository';
import { NAT_RULES_REPOSITORY_TOKEN } from 'src/domain/repositories/nat-rules.repository';
import { TOKEN_SERVICE_TOKEN } from 'src/application/ports/token-service.interface';
import { ConfigController } from 'src/presentation/controllers/config.controller';
import { RULES_REPOSITORY_TOKEN } from 'src/domain/repositories/rules-repository';
import { ROLE_REPOSITORY_TOKEN } from 'src/domain/repositories/role.repository';
import { USER_REPOSITORY_TOKEN } from 'src/domain/repositories/user.repository';
import { ZONE_REPOSITORY_TOKEN } from 'src/domain/repositories/zone.repository';
import { TokenService } from 'src/infrastructure/adapters/jwt-token.service';
import { FileStore } from 'src/infrastructure/persistence/json/file-store';
import { Mutex } from 'src/infrastructure/persistence/json/file-mutex';
import { JwtService } from '@nestjs/jwt';
import { Module } from '@nestjs/common';

@Module({
  imports: [],
  controllers: [ConfigController],
  providers: [
    ApplyConfigSnapshotUseCase,
    GetConfigHistoryUseCase,
    FileStore,
    Mutex,
    {
      provide: TOKEN_SERVICE_TOKEN,
      useClass: TokenService,
    },
    {
      provide: CONFIG_SNAPSHOT_REPOSITORY_TOKEN,
      useClass: JsonConfigSnapshotRepository,
    },
    {
      provide: NAT_RULES_REPOSITORY_TOKEN,
      useClass: JsonNatRuleRepository,
    },
    {
      provide: PERMISSION_REPOSITORY_TOKEN,
      useClass: JsonPermissionRepository,
    },
    {
      provide: ROLE_REPOSITORY_TOKEN,
      useClass: JsonRoleRepository,
    },
    {
      provide: RULES_REPOSITORY_TOKEN,
      useClass: JsonRuleRepository,
    },
    {
      provide: USER_REPOSITORY_TOKEN,
      useClass: JsonUserRepository,
    },
    {
      provide: ZONE_PAIR_REPOSITORY_TOKEN,
      useClass: JsonZonePairRepository,
    },
    {
      provide: ZONE_REPOSITORY_TOKEN,
      useClass: JsonZoneRepository,
    },
    {
      provide: USER_ROLES_REPOSITORY_TOKEN,
      useClass: JsonUserRoleRepository,
    },
    {
      provide: ROLE_PERMISSIONS_REPOSITORY_TOKEN,
      useClass: JsonRolePermissionsRepository,
    },
    JwtService,
  ],
  exports: [],
})
export class ConfigSnapshotModule {}
