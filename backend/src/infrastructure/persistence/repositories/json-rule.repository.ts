import { IRulesRepository } from 'src/domain/repositories/rules-repository';
import { FirewallRule } from 'src/domain/entities/firewall-rule.entity';
import { RulesFile, RulesFileSchema } from '../schemas/rules.schema';
import { RuleJsonMapper } from '../mappers/rule-json.mapper';
import { FileStore } from '../json/file-store';
import { Mutex } from '../json/file-mutex';
import { Inject } from '@nestjs/common';
import { join } from 'node:path';

export class JsonRuleRepository implements IRulesRepository {
  private readonly filePath: string = join(process.cwd(), 'rules.json');
  constructor(
    @Inject(FileStore) private readonly fileStore: FileStore,
    @Inject(Mutex) private readonly mutex: Mutex,
  ) {}

  private async readPayload(): Promise<RulesFile> {
    const raw = await this.fileStore.readJsonOrDefault<unknown>(this.filePath, {
      items: [],
    });

    return RulesFileSchema.parse(raw);
  }

  async save(rule: FirewallRule): Promise<void> {
    const rules = await this.readPayload();
    const next = RuleJsonMapper.toRecord(rule);

    const existingRow = await this.findById(rule.getId());
    if (existingRow) {
      rules.items = rules.items.map((r) => (r.id === rule.getId() ? next : r));
    } else {
      rules.items.push(next);
    }

    await this.mutex.runExclusive(async () => {
      await this.fileStore.writeJsonAtomic(this.filePath, rules);
    });
  }

  async findById(id: string): Promise<FirewallRule | null> {
    const rules = await this.readPayload();
    const ruleById = rules.items.find((r) => r.id === id);

    if (!ruleById) return null;

    return RuleJsonMapper.toDomain(ruleById);
  }

  async findAll(): Promise<FirewallRule[]> {
    const rules = await this.readPayload();
    if (!rules.items.length) return [];

    return rules.items.map((r) => RuleJsonMapper.toDomain(r));
  }

  async findActive(): Promise<FirewallRule[]> {
    const payload = await this.readPayload();
    payload.items = payload.items.filter((r) => r.isActive);

    return payload.items.map((r) => RuleJsonMapper.toDomain(r));
  }

  async finfByName(name: string): Promise<FirewallRule | null> {
    const rules = await this.readPayload();
    rules.items = rules.items.filter((r) => r.name === name);

    return rules.items.length > 0
      ? RuleJsonMapper.toDomain(rules.items[0])
      : null;
  }

  async delete(id: string): Promise<void> {
    const rules = await this.readPayload();

    rules.items = rules.items.filter((r) => r.id !== id);

    await this.mutex.runExclusive(async () => {
      await this.fileStore.writeJsonAtomic(this.filePath, rules);
    });
  }
}
