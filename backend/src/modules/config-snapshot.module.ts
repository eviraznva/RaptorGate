import { join } from "node:path";
import { Module } from "@nestjs/common";
import { ConfigService } from "@nestjs/config";
import { JwtService } from "@nestjs/jwt";
import { ClientsModule, Transport } from "@nestjs/microservices";
import { CONFIG_SNAPSHOT_PUSH_SERVICE_TOKEN } from "../application/ports/config-snapshot-push-service.interface.js";
import { RAPTOR_LANG_VALIDATION_SERVICE_TOKEN } from "../application/ports/raptor-lang-validation-service.interface.js";
import { TOKEN_SERVICE_TOKEN } from "../application/ports/token-service.interface.js";
import { ApplyConfigSnapshotUseCase } from "../application/use-cases/apply-config-snapshot.use-case.js";
import { ExportConfigUseCase } from "../application/use-cases/export-config.use-case.js";
import { GetConfigHistoryUseCase } from "../application/use-cases/get-config-history.use-case.js";
import { ImportConfigUseCase } from "../application/use-cases/import-config.use-case.js";
import { RollbackConfigUseCase } from "../application/use-cases/rollback-config.use-case.js";
import { CONFIG_SNAPSHOT_REPOSITORY_TOKEN } from "../domain/repositories/config-snapshot.repository.js";
import { NAT_RULES_REPOSITORY_TOKEN } from "../domain/repositories/nat-rules.repository.js";
import { PERMISSION_REPOSITORY_TOKEN } from "../domain/repositories/permission.repository.js";
import { ROLE_REPOSITORY_TOKEN } from "../domain/repositories/role.repository.js";
import { ROLE_PERMISSIONS_REPOSITORY_TOKEN } from "../domain/repositories/role-permissions.repository.js";
import { RULES_REPOSITORY_TOKEN } from "../domain/repositories/rules-repository.js";
import { USER_REPOSITORY_TOKEN } from "../domain/repositories/user.repository.js";
import { USER_ROLES_REPOSITORY_TOKEN } from "../domain/repositories/user-roles.repository.js";
import { ZONE_REPOSITORY_TOKEN } from "../domain/repositories/zone.repository.js";
import { ZONE_PAIR_REPOSITORY_TOKEN } from "../domain/repositories/zone-pair.repository.js";
import {
  CONFIG_SNAPSHOT_PUSH_GRPC_CLIENT_TOKEN,
  GrpcConfigSnapshotPushService,
} from "../infrastructure/adapters/grpc-config-snapshot-push.service.js";
import {
  GrpcRaptorLangValidationService,
  RAPTOR_LANG_VALIDATION_GRPC_CLIENT_TOKEN,
} from "../infrastructure/adapters/grpc-raptor-lang-validation.service.js";
import { TokenService } from "../infrastructure/adapters/jwt-token.service.js";
import { Mutex } from "../infrastructure/persistence/json/file-mutex.js";
import { FileStore } from "../infrastructure/persistence/json/file-store.js";
import { JsonConfigSnapshotRepository } from "../infrastructure/persistence/repositories/json-config-snapshot.repository.js";
import { JsonNatRuleRepository } from "../infrastructure/persistence/repositories/json-nat-rule.repository.js";
import { JsonPermissionRepository } from "../infrastructure/persistence/repositories/json-permission.repository.js";
import { JsonRoleRepository } from "../infrastructure/persistence/repositories/json-role.repository.js";
import { JsonRolePermissionsRepository } from "../infrastructure/persistence/repositories/json-role-permissions.repository.js";
import { JsonRuleRepository } from "../infrastructure/persistence/repositories/json-rule.repository.js";
import { JsonUserRepository } from "../infrastructure/persistence/repositories/json-user.repository.js";
import { JsonUserRoleRepository } from "../infrastructure/persistence/repositories/json-user-role.repository.js";
import { JsonZoneRepository } from "../infrastructure/persistence/repositories/json-zone.repository.js";
import { JsonZonePairRepository } from "../infrastructure/persistence/repositories/json-zone-pair.repository.js";
import { ConfigController } from "../presentation/controllers/config.controller.js";
import { Env } from "../shared/config/env.validation.js";

@Module({
  imports: [
    ClientsModule.registerAsync([
      {
        name: CONFIG_SNAPSHOT_PUSH_GRPC_CLIENT_TOKEN,
        useFactory: (configService: ConfigService<Env, true>) => {
          const firewallSocketPath = configService.get(
            "FIREWALL_GRPC_SOCKET_PATH",
            {
              infer: true,
            },
          );

          const grpcUrl = firewallSocketPath.startsWith("unix://")
            ? firewallSocketPath
            : `unix://${join(process.cwd(), firewallSocketPath)}`;

          return {
            transport: Transport.GRPC,
            options: {
              package: "raptorgate.services",
              protoPath: join(
                process.cwd(),
                "..",
                "proto",
                "services",
                "config_snapshot_service.proto",
              ),
              loader: {
                includeDirs: [join(process.cwd(), "..", "proto")],
              },
              url: grpcUrl,
            },
          };
        },
        inject: [ConfigService],
      },
      {
        name: RAPTOR_LANG_VALIDATION_GRPC_CLIENT_TOKEN,
        useFactory: (configService: ConfigService<Env, true>) => {
          const backendSocketPath = configService.get("GRPC_SOCKET_PATH", {
            infer: true,
          });

          const firewallSocketPath = configService.get(
            "FIREWALL_GRPC_SOCKET_PATH",
            {
              infer: true,
            },
          );

          const resolveGrpcUrl = (path: string): string =>
            path.startsWith("unix://")
              ? path
              : `unix://${join(process.cwd(), path)}`;

          const backendGrpcUrl = resolveGrpcUrl(backendSocketPath);
          const firewallGrpcUrl = resolveGrpcUrl(firewallSocketPath);

          if (backendGrpcUrl === firewallGrpcUrl) {
            throw new Error(
              "FIREWALL_GRPC_SOCKET_PATH must point to firewall validation service and cannot equal GRPC_SOCKET_PATH.",
            );
          }

          const grpcUrl = firewallGrpcUrl;

          return {
            transport: Transport.GRPC,
            options: {
              package: "raptorgate.control",
              protoPath: join(
                process.cwd(),
                "..",
                "proto",
                "control",
                "validation_service.proto",
              ),
              loader: {
                includeDirs: [join(process.cwd(), "..", "proto")],
              },
              url: grpcUrl,
            },
          };
        },
        inject: [ConfigService],
      },
    ]),
  ],
  controllers: [ConfigController],
  providers: [
    ApplyConfigSnapshotUseCase,
    GetConfigHistoryUseCase,
    RollbackConfigUseCase,
    ExportConfigUseCase,
    ImportConfigUseCase,
    GrpcConfigSnapshotPushService,
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
    {
      provide: CONFIG_SNAPSHOT_PUSH_SERVICE_TOKEN,
      useExisting: GrpcConfigSnapshotPushService,
    },
    {
      provide: RAPTOR_LANG_VALIDATION_SERVICE_TOKEN,
      useClass: GrpcRaptorLangValidationService,
    },
    JwtService,
  ],
  exports: [],
})
export class ConfigSnapshotModule {}
