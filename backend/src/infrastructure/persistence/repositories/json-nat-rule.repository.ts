import { join } from "node:path";
import { Inject, Injectable } from "@nestjs/common";
import type {
  NatRule,
  NatRuleAction,
} from "../../../domain/entities/nat-rule.entity.js";
import type { INatRulesRepository } from "../../../domain/repositories/nat-rules.repository.js";
import type { NatProtocol } from "../../grpc/generated/common/common.js";
import { Mutex } from "../json/file-mutex.js";
import { FileStore } from "../json/file-store.js";
import { NatRuleJsonMapper } from "../mappers/nat-rule-json.mapper.js";
import {
  NatRulesFile,
  NatRulesFileSchema,
} from "../schemas/nat-rules.schema.js";

@Injectable()
export class JsonNatRuleRepository implements INatRulesRepository {
  private readonly filePath = join(
    process.cwd(),
    "data/json-db/nat_rules.json",
  );

  constructor(
    @Inject(FileStore) private readonly fileStore: FileStore,
    @Inject(Mutex) private readonly mutex: Mutex,
  ) {}

  private async readPayload(): Promise<NatRulesFile> {
    const raw = await this.fileStore.readJsonOrDefault<unknown>(this.filePath, {
      items: [],
    });

    return NatRulesFileSchema.parse(raw);
  }

  async save(natRule: NatRule, createdBy?: string): Promise<void> {
    await this.mutex.runExclusive(async () => {
      const payload = await this.readPayload();
      const idx = payload.items.findIndex((i) => i.id === natRule.getId());
      const nextCreatedBy = idx >= 0 ? payload.items[idx].createdBy : createdBy;

      if (!nextCreatedBy) {
        throw new Error("createdBy is required when creating a NAT rule");
      }

      const next = NatRuleJsonMapper.toRecord(natRule, nextCreatedBy);

      if (idx >= 0) {
        payload.items[idx] = next;
      } else {
        payload.items.push(next);
      }

      await this.fileStore.writeJsonAtomic(this.filePath, payload);
    });
  }

  async overwriteAll(natRules: NatRule[]): Promise<void> {
    const toNatRules = natRules.map((natRule) =>
      NatRuleJsonMapper.toRecord(natRule, crypto.randomUUID()),
    );

    await this.mutex.runExclusive(async () => {
      await this.fileStore.writeJsonAtomic(this.filePath, {
        items: toNatRules,
      });
    });
  }

  async findById(id: string): Promise<NatRule | null> {
    const payload = await this.readPayload();
    const row = payload.items.find((i) => i.id === id);

    return row ? NatRuleJsonMapper.toDomain(row) : null;
  }

  async findAll(): Promise<NatRule[]> {
    const payload = await this.readPayload();

    return payload.items.map((i) => NatRuleJsonMapper.toDomain(i));
  }

  async findActive(): Promise<NatRule[]> {
    const payload = await this.readPayload();

    return payload.items
      .filter((i) => i.isActive)
      .map((i) => NatRuleJsonMapper.toDomain(i));
  }

  async findByActionKind(kind: NatRuleAction["$case"]): Promise<NatRule[]> {
    const rules = await this.findAll();

    return rules.filter((rule) => rule.getActionKind() === kind);
  }

  async findByProtocol(protocol: NatProtocol): Promise<NatRule[]> {
    const rules = await this.findAll();

    return rules.filter((rule) => rule.getProtocol() === protocol);
  }

  async delete(id: string): Promise<void> {
    await this.mutex.runExclusive(async () => {
      const payload = await this.readPayload();
      payload.items = payload.items.filter((i) => i.id !== id);

      await this.fileStore.writeJsonAtomic(this.filePath, payload);
    });
  }
}
