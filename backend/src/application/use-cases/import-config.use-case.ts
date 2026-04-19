import { hash } from "node:crypto";
import { BadRequestException, Inject, Injectable, Logger } from "@nestjs/common";
import { ConfigurationSnapshot } from "src/domain/entities/configuration-snapshot.entity";
import { FirewallRule } from "src/domain/entities/firewall-rule.entity";
import { NatRule } from "src/domain/entities/nat-rule.entity";
import { Zone } from "src/domain/entities/zone.entity";
import { ZonePair } from "src/domain/entities/zone-pair.entity";
import { AccessTokenIsInvalidException } from "src/domain/exceptions/acces-token-is-invalid.exception";
import {
  CONFIG_SNAPSHOT_REPOSITORY_TOKEN,
  type IConfigSnapshotRepository,
} from "src/domain/repositories/config-snapshot.repository";
import {
  type INatRulesRepository,
  NAT_RULES_REPOSITORY_TOKEN,
} from "src/domain/repositories/nat-rules.repository";
import {
  type IRulesRepository,
  RULES_REPOSITORY_TOKEN,
} from "src/domain/repositories/rules-repository";
import {
  type IZoneRepository,
  ZONE_REPOSITORY_TOKEN,
} from "src/domain/repositories/zone.repository";
import {
  type IZonePairRepository,
  ZONE_PAIR_REPOSITORY_TOKEN,
} from "src/domain/repositories/zone-pair.repository";
import { Checksum } from "src/domain/value-objects/checksum.vo";
import { IpAddress } from "src/domain/value-objects/ip-address.vo";
import { NatType } from "src/domain/value-objects/nat-type.vo";
import { Port } from "src/domain/value-objects/port.vo";
import { Priority } from "src/domain/value-objects/priority.vo";
import { SnapshotType } from "src/domain/value-objects/snapshot-type.vo";
import { ImportConfigDto } from "../dtos/import-config.dto";
import { ImportConfigResponseDto } from "../dtos/import-config-response.dto";
import {
  CONFIG_SNAPSHOT_PUSH_SERVICE_TOKEN,
  type IConfigSnapshotPushService,
} from "../ports/config-snapshot-push-service.interface";
import {
  type IRaptorLangValidationService,
  RAPTOR_LANG_VALIDATION_SERVICE_TOKEN,
} from "../ports/raptor-lang-validation-service.interface";
import {
  type ITokenService,
  TOKEN_SERVICE_TOKEN,
} from "../ports/token-service.interface";

@Injectable()
export class ImportConfigUseCase {
  private readonly logger = new Logger(ImportConfigUseCase.name);

  constructor(
    @Inject(CONFIG_SNAPSHOT_REPOSITORY_TOKEN)
    private readonly configSnapshotRepository: IConfigSnapshotRepository,
    @Inject(RAPTOR_LANG_VALIDATION_SERVICE_TOKEN)
    private readonly raptorLangValidationService: IRaptorLangValidationService,
    @Inject(TOKEN_SERVICE_TOKEN)
    private readonly tokenService: ITokenService,
    @Inject(CONFIG_SNAPSHOT_PUSH_SERVICE_TOKEN)
    private readonly configSnapshotPushService: IConfigSnapshotPushService,
    @Inject(ZONE_REPOSITORY_TOKEN)
    private readonly zoneRepository: IZoneRepository,
    @Inject(ZONE_PAIR_REPOSITORY_TOKEN)
    private readonly zonePairRepository: IZonePairRepository,
    @Inject(RULES_REPOSITORY_TOKEN)
    private readonly rulesRepository: IRulesRepository,
    @Inject(NAT_RULES_REPOSITORY_TOKEN)
    private readonly natRulesRepository: INatRulesRepository,
  ) {}

  async execute(dto: ImportConfigDto): Promise<ImportConfigResponseDto> {
    const claims = this.tokenService.decodeAccessToken(dto.accessToken);
    if (!claims) throw new AccessTokenIsInvalidException();

    const payloadJsonStr =
      typeof dto.snapshotData.payloadJson === "string"
        ? dto.snapshotData.payloadJson
        : JSON.stringify(dto.snapshotData.payloadJson);

    const calculatedChecksum = hash("sha256", payloadJsonStr);
    if (calculatedChecksum !== dto.snapshotData.checksum) {
      throw new BadRequestException(
        "Invalid checksum: imported payload does not match the provided checksum.",
      );
    }

    const allConfigSnapshots =
      await this.configSnapshotRepository.findAllSnapshots();

    const highestVersionNumber = allConfigSnapshots.reduce((prev, curr) => {
      return curr.getVersionNumber() > prev ? curr.getVersionNumber() : prev;
    }, 0);

    const newVersionNumber = highestVersionNumber + 1;

    const newId = crypto.randomUUID();

    const importedSnapshot = ConfigurationSnapshot.create(
      newId,
      newVersionNumber,
      SnapshotType.create(dto.snapshotData.snapshotType),
      Checksum.create(calculatedChecksum),
      dto.snapshotData.isActive,
      dto.snapshotData.payloadJson,
      dto.snapshotData.changeSummary || "Imported config via API",
      new Date(),
      claims.sub,
    );
    const payload = importedSnapshot.deserializePayload();

    await Promise.all(
      payload.bundle.rules.items.map((rule: any) =>
        this.raptorLangValidationService.validateRaptorLang(rule.content),
      ),
    );

    if (dto.snapshotData.isActive) {
      const activeZones = payload.bundle.zones.items.map((z: any) =>
        Zone.create(
          z.id,
          z.name,
          z.description,
          z.isActive,
          new Date(z.createdAt),
          z.createdBy,
        ),
      );

      const activeZonePairs = payload.bundle.zone_pairs.items.map((zp: any) =>
        ZonePair.create(
          zp.id,
          zp.srcZoneId,
          zp.dstZoneId,
          zp.defaultPolicy,
          new Date(zp.createdAt),
          zp.createdBy,
        ),
      );

      const activeRules = payload.bundle.rules.items.map((r: any) =>
        FirewallRule.create(
          r.id,
          r.name,
          r.description,
          r.zonePairId,
          r.isActive,
          r.content,
          Priority.create(r.priority.value),
          new Date(r.createdAt),
          new Date(r.updatedAt),
          r.createdBy,
        ),
      );

      const activeNatRules = payload.bundle.nat_rules.items.map((n: any) =>
        NatRule.create(
          n.id,
          NatType.create(n.type.value),
          n.isActive,
          n.sourceIp ? IpAddress.create(n.sourceIp.value) : null,
          n.destinationIp ? IpAddress.create(n.destinationIp.value) : null,
          n.sourcePort ? Port.create(n.sourcePort.value) : null,
          n.destinationPort ? Port.create(n.destinationPort.value) : null,
          n.translatedIp ? IpAddress.create(n.translatedIp.value) : null,
          n.translatedPort ? Port.create(n.translatedPort.value) : null,
          Priority.create(n.priority.value),
          new Date(n.createdAt),
          new Date(n.updatedAt),
        ),
      );

      await this.zoneRepository.overwriteAll(activeZones);
      await this.zonePairRepository.overwriteAll(activeZonePairs);
      await this.rulesRepository.overwriteAll(activeRules);
      await this.natRulesRepository.overwriteAll(activeNatRules);

      const currentActiveSnapshot = allConfigSnapshots.find((s) =>
        s.getIsActive(),
      );
      if (currentActiveSnapshot) {
        currentActiveSnapshot.setIsActive(false);

        await this.configSnapshotRepository.save(currentActiveSnapshot);
      }
    }

    await this.configSnapshotRepository.save(importedSnapshot);

    if (dto.snapshotData.isActive) {
      await this.configSnapshotPushService.pushActiveConfigSnapshot(
        importedSnapshot,
        "import",
      );
    }

    this.logger.log({
      event: "config_snapshot.import.succeeded",
      message: "configuration snapshot imported",
      actorId: claims.sub,
      snapshotId: importedSnapshot.getId(),
      versionNumber: importedSnapshot.getVersionNumber(),
      checksum: calculatedChecksum,
      isActive: dto.snapshotData.isActive,
      counts: {
        rules: payload.bundle.rules.items.length,
        zones: payload.bundle.zones.items.length,
        zonePairs: payload.bundle.zone_pairs.items.length,
        natRules: payload.bundle.nat_rules.items.length,
      },
    });

    return {
      configSnapshot: importedSnapshot,
    };
  }
}
