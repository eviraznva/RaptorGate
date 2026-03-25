import { INatRulesRepository } from 'src/domain/repositories/nat-rules.repository';
import { NatRulesFile, NatRulesFileSchema } from '../schemas/nat-rules.schema';
import { NatRuleJsonMapper } from '../mappers/nat-rule-json.mapper';
import { NatRule } from 'src/domain/entities/nat-rule.entity';
import { Inject, Injectable } from '@nestjs/common';
import { FileStore } from '../json/file-store';
import { Mutex } from '../json/file-mutex';
import { join } from 'node:path';

@Injectable()
export class JsonNatRuleRepository implements INatRulesRepository {
  private readonly filePath = join(
    process.cwd(),
    'data/json-db/nat_rules.json',
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
        throw new Error('createdBy is required when creating a NAT rule');
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

  async findByType(type: string): Promise<NatRule[]> {
    const payload = await this.readPayload();

    return payload.items
      .filter((i) => i.type === type)
      .map((i) => NatRuleJsonMapper.toDomain(i));
  }

  async findBySourceIp(sourceIp: string): Promise<NatRule[]> {
    const payload = await this.readPayload();

    return payload.items
      .filter((i) => i.srcIp === sourceIp)
      .map((i) => NatRuleJsonMapper.toDomain(i));
  }

  async findByDestinationIp(destinationIp: string): Promise<NatRule[]> {
    const payload = await this.readPayload();

    return payload.items
      .filter((i) => i.dstIp === destinationIp)
      .map((i) => NatRuleJsonMapper.toDomain(i));
  }

  async findBySourcePort(sourcePort: number): Promise<NatRule[]> {
    const payload = await this.readPayload();

    return payload.items
      .filter((i) => i.srcPort === sourcePort)
      .map((i) => NatRuleJsonMapper.toDomain(i));
  }

  async findByDestinationPort(destinationPort: number): Promise<NatRule[]> {
    const payload = await this.readPayload();

    return payload.items
      .filter((i) => i.dstPort === destinationPort)
      .map((i) => NatRuleJsonMapper.toDomain(i));
  }

  async delete(id: string): Promise<void> {
    await this.mutex.runExclusive(async () => {
      const payload = await this.readPayload();
      payload.items = payload.items.filter((i) => i.id !== id);

      await this.fileStore.writeJsonAtomic(this.filePath, payload);
    });
  }
}
