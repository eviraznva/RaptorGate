import { JsonRolePermissionsRepository } from '../infrastructure/persistence/repositories/json-role-permissions.repository.js';
import { JsonConfigSnapshotRepository } from '../infrastructure/persistence/repositories/json-config-snapshot.repository.js';
import { JsonPermissionRepository } from '../infrastructure/persistence/repositories/json-permission.repository.js';
import { JsonUserRoleRepository } from '../infrastructure/persistence/repositories/json-user-role.repository.js';
import { JsonZonePairRepository } from '../infrastructure/persistence/repositories/json-zone-pair.repository.js';
import { JsonNatRuleRepository } from '../infrastructure/persistence/repositories/json-nat-rule.repository.js';
import { ROLE_PERMISSIONS_REPOSITORY_TOKEN } from '../domain/repositories/role-permissions.repository.js';
import { ApplyConfigSnapshotUseCase } from '../application/use-cases/apply-config-snapshot.use-case.js';
import { CONFIG_SNAPSHOT_REPOSITORY_TOKEN } from '../domain/repositories/config-snapshot.repository.js';
import { JsonRoleRepository } from '../infrastructure/persistence/repositories/json-role.repository.js';
import { JsonRuleRepository } from '../infrastructure/persistence/repositories/json-rule.repository.js';
import { JsonUserRepository } from '../infrastructure/persistence/repositories/json-user.repository.js';
import { JsonZoneRepository } from '../infrastructure/persistence/repositories/json-zone.repository.js';
import { GetConfigHistoryUseCase } from '../application/use-cases/get-config-history.use-case.js';
import { RollbackConfigUseCase } from '../application/use-cases/rollback-config.use-case.js';
import { PERMISSION_REPOSITORY_TOKEN } from '../domain/repositories/permission.repository.js';
import { USER_ROLES_REPOSITORY_TOKEN } from '../domain/repositories/user-roles.repository.js';
import { NAT_RULES_REPOSITORY_TOKEN } from '../domain/repositories/nat-rules.repository.js';
import { ZONE_PAIR_REPOSITORY_TOKEN } from '../domain/repositories/zone-pair.repository.js';
import { TOKEN_SERVICE_TOKEN } from '../application/ports/token-service.interface.js';
import { ConfigController } from '../presentation/controllers/config.controller.js';
import { RULES_REPOSITORY_TOKEN } from '../domain/repositories/rules-repository.js';
import { ROLE_REPOSITORY_TOKEN } from '../domain/repositories/role.repository.js';
import { USER_REPOSITORY_TOKEN } from '../domain/repositories/user.repository.js';
import { ZONE_REPOSITORY_TOKEN } from '../domain/repositories/zone.repository.js';
import { TokenService } from '../infrastructure/adapters/jwt-token.service.js';
import { FileStore } from '../infrastructure/persistence/json/file-store.js';
import { Mutex } from '../infrastructure/persistence/json/file-mutex.js';
import { JwtService } from '@nestjs/jwt';
import { Module } from '@nestjs/common';

@Module({
  imports: [],
  controllers: [ConfigController],
  providers: [
    ApplyConfigSnapshotUseCase,
    GetConfigHistoryUseCase,
    RollbackConfigUseCase,
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
