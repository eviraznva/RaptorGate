import { hash, randomUUID } from 'node:crypto';
import { NotFoundException } from '@nestjs/common';
import { ConfigurationSnapshot } from '../../domain/entities/configuration-snapshot.entity.js';
import { SslBypassEntry } from '../../domain/entities/ssl-bypass-entry.entity.js';
import type { IConfigSnapshotRepository } from '../../domain/repositories/config-snapshot.repository.js';
import type { ConfigSnapshotPayload } from '../../domain/value-objects/config-snapshot-payload.interface.js';
import { Checksum } from '../../domain/value-objects/checksum.vo.js';
import { SnapshotType } from '../../domain/value-objects/snapshot-type.vo.js';
import type { IConfigSnapshotPushService } from '../ports/config-snapshot-push-service.interface.js';

export async function pushSslBypassSnapshot(
  configSnapshotRepository: IConfigSnapshotRepository,
  configSnapshotPushService: IConfigSnapshotPushService,
  bypassDomains: SslBypassEntry[],
  actorId: string,
): Promise<ConfigurationSnapshot> {
  const activeSnapshot = await configSnapshotRepository.findActiveSnapshot();
  if (!activeSnapshot) throw new NotFoundException('Active configuration snapshot not found');

  const payload = activeSnapshot.deserializePayload();
  const nextPayload = withSslBypassList(payload, bypassDomains);
  const allSnapshots = await configSnapshotRepository.findAllSnapshots();
  const highestVersionNumber = allSnapshots.reduce((prev, curr) => {
    if (curr.getVersionNumber() > prev) return curr.getVersionNumber();
    return prev;
  }, 0);
  const checksum = hash('sha256', JSON.stringify(nextPayload));
  const nextSnapshot = ConfigurationSnapshot.create(
    randomUUID(),
    highestVersionNumber + 1,
    SnapshotType.create('auto_save'),
    Checksum.create(checksum),
    true,
    nextPayload,
    'Update TLS inspection bypass domains',
    new Date(),
    actorId,
  );

  await configSnapshotRepository.save(nextSnapshot);
  activeSnapshot.setIsActive(false);
  await configSnapshotRepository.save(activeSnapshot);
  await configSnapshotPushService.pushActiveConfigSnapshot(
    nextSnapshot,
    'ssl_bypass_update',
  );

  return nextSnapshot;
}

function withSslBypassList(
  payload: ConfigSnapshotPayload,
  bypassDomains: SslBypassEntry[],
): ConfigSnapshotPayload {
  return {
    bundle: {
      ...payload.bundle,
      ssl_bypass_list: {
        items: bypassDomains,
      },
    },
  };
}
