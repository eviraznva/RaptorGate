import { beforeEach, describe, expect, it, jest } from 'bun:test';
import { BadRequestException } from '@nestjs/common';
import { ConfigurationSnapshot } from '../../domain/entities/configuration-snapshot.entity.js';
import { SslBypassEntry } from '../../domain/entities/ssl-bypass-entry.entity.js';
import type { IConfigSnapshotRepository } from '../../domain/repositories/config-snapshot.repository.js';
import type { ISslBypassRepository } from '../../domain/repositories/ssl-bypass.repository.js';
import {
  DEFAULT_TLS_INSPECTION_POLICY,
  emptyIdentityConfigPayload,
  type ConfigSnapshotPayload,
} from '../../domain/value-objects/config-snapshot-payload.interface.js';
import { Checksum } from '../../domain/value-objects/checksum.vo.js';
import { SnapshotType } from '../../domain/value-objects/snapshot-type.vo.js';
import type { IConfigSnapshotPushService } from '../ports/config-snapshot-push-service.interface.js';
import type { ITokenService } from '../ports/token-service.interface.js';
import { CreateSslBypassDomainUseCase } from './create-ssl-bypass-domain.use-case.js';
import { DeleteSslBypassDomainUseCase } from './delete-ssl-bypass-domain.use-case.js';
import { GetSslBypassDomainsUseCase } from './get-ssl-bypass-domains.use-case.js';

describe('SSL bypass domain use cases', () => {
  let bypassEntries: SslBypassEntry[];
  let snapshots: ConfigurationSnapshot[];
  let sslBypassRepository: jest.Mocked<ISslBypassRepository>;
  let configSnapshotRepository: jest.Mocked<IConfigSnapshotRepository>;
  let configSnapshotPushService: jest.Mocked<IConfigSnapshotPushService>;
  let tokenService: jest.Mocked<ITokenService>;

  beforeEach(() => {
    bypassEntries = [];
    snapshots = [makeSnapshot(1, true, [])];
    sslBypassRepository = makeSslBypassRepository();
    configSnapshotRepository = makeConfigSnapshotRepository();
    configSnapshotPushService = {
      pushActiveConfigSnapshot: jest.fn(async () => undefined),
      factoryReset: jest.fn(),
    } as unknown as jest.Mocked<IConfigSnapshotPushService>;
    tokenService = {
      generateAccessToken: jest.fn(),
      generateRefreshToken: jest.fn(),
      generateTokenPair: jest.fn(),
      verifyAccessToken: jest.fn(),
      decodeAccessToken: jest.fn(() => ({
        sub: 'user-1',
        username: 'admin',
      })),
    };
  });

  it('lists all configured bypass domains', async () => {
    bypassEntries.push(
      SslBypassEntry.create(
        '11111111-1111-1111-1111-111111111111',
        'www.google.com',
        'manual bypass',
        true,
        new Date('2026-06-05T10:00:00.000Z'),
      ),
    );

    const useCase = new GetSslBypassDomainsUseCase(sslBypassRepository);

    const result = await useCase.execute();

    expect(result.bypassDomains).toHaveLength(1);
    expect(result.bypassDomains[0]?.domain).toBe('www.google.com');
  });

  it('adds an active bypass domain and pushes a new active snapshot', async () => {
    const useCase = new CreateSslBypassDomainUseCase(
      sslBypassRepository,
      configSnapshotRepository,
      configSnapshotPushService,
      tokenService,
    );

    const result = await useCase.execute({
      domain: 'www.google.com',
      reason: 'manual bypass',
      accessToken: 'token',
    });

    expect(result.bypassDomain.domain).toBe('www.google.com');
    expect(result.bypassDomain.reason).toBe('manual bypass');
    expect(result.bypassDomain.isActive).toBe(true);
    expect(bypassEntries).toHaveLength(1);
    expect(snapshots).toHaveLength(2);
    expect(snapshots[0]?.getIsActive()).toBe(false);
    expect(snapshots[1]?.getIsActive()).toBe(true);
    expect(
      snapshots[1]
        ?.deserializePayload()
        .bundle.ssl_bypass_list.items.map((entry) => entry.getDomain()),
    ).toEqual(['www.google.com']);
    expect(configSnapshotPushService.pushActiveConfigSnapshot).toHaveBeenCalledWith(
      snapshots[1],
      'ssl_bypass_update',
    );
  });

  it('rejects duplicate bypass domains', async () => {
    bypassEntries.push(
      SslBypassEntry.create(
        '11111111-1111-1111-1111-111111111111',
        'www.google.com',
        'manual bypass',
        true,
        new Date('2026-06-05T10:00:00.000Z'),
      ),
    );
    const useCase = new CreateSslBypassDomainUseCase(
      sslBypassRepository,
      configSnapshotRepository,
      configSnapshotPushService,
      tokenService,
    );

    await expect(
      useCase.execute({
        domain: 'WWW.GOOGLE.COM',
        reason: 'manual bypass',
        accessToken: 'token',
      }),
    ).rejects.toBeInstanceOf(BadRequestException);
    expect(configSnapshotPushService.pushActiveConfigSnapshot).not.toHaveBeenCalled();
  });

  it('deletes a bypass domain and pushes a new active snapshot', async () => {
    bypassEntries.push(
      SslBypassEntry.create(
        '11111111-1111-1111-1111-111111111111',
        'www.google.com',
        'manual bypass',
        true,
        new Date('2026-06-05T10:00:00.000Z'),
      ),
    );
    snapshots = [makeSnapshot(1, true, [...bypassEntries])];
    configSnapshotRepository = makeConfigSnapshotRepository();
    const useCase = new DeleteSslBypassDomainUseCase(
      sslBypassRepository,
      configSnapshotRepository,
      configSnapshotPushService,
      tokenService,
    );

    await useCase.execute({
      id: '11111111-1111-1111-1111-111111111111',
      accessToken: 'token',
    });

    expect(bypassEntries).toHaveLength(0);
    expect(snapshots).toHaveLength(2);
    expect(snapshots[0]?.getIsActive()).toBe(false);
    expect(snapshots[1]?.deserializePayload().bundle.ssl_bypass_list.items).toEqual([]);
    expect(configSnapshotPushService.pushActiveConfigSnapshot).toHaveBeenCalledWith(
      snapshots[1],
      'ssl_bypass_update',
    );
  });

  function makeSslBypassRepository(): jest.Mocked<ISslBypassRepository> {
    return {
      save: jest.fn(async (entry: SslBypassEntry) => {
        const index = bypassEntries.findIndex((item) => item.getId() === entry.getId());
        if (index >= 0) {
          bypassEntries[index] = entry;
          return;
        }
        bypassEntries.push(entry);
      }),
      findById: jest.fn(async (id: string) => bypassEntries.find((entry) => entry.getId() === id) ?? null),
      findAll: jest.fn(async () => [...bypassEntries]),
      findActive: jest.fn(async () => bypassEntries.filter((entry) => entry.getIsActive())),
      overwriteAll: jest.fn(async (entries: SslBypassEntry[]) => {
        bypassEntries = [...entries];
      }),
      delete: jest.fn(async (id: string) => {
        bypassEntries = bypassEntries.filter((entry) => entry.getId() !== id);
      }),
    };
  }

  function makeConfigSnapshotRepository(): jest.Mocked<IConfigSnapshotRepository> {
    return {
      save: jest.fn(async (snapshot: ConfigurationSnapshot) => {
        const index = snapshots.findIndex((item) => item.getId() === snapshot.getId());
        if (index >= 0) {
          snapshots[index] = snapshot;
          return;
        }
        snapshots.push(snapshot);
      }),
      findActiveSnapshot: jest.fn(async () => snapshots.find((snapshot) => snapshot.getIsActive()) ?? null),
      findAllSnapshots: jest.fn(async () => [...snapshots]),
      findById: jest.fn(async (id: string) => snapshots.find((snapshot) => snapshot.getId() === id) ?? null),
    };
  }
});

function makeSnapshot(
  versionNumber: number,
  isActive: boolean,
  bypassEntries: SslBypassEntry[],
): ConfigurationSnapshot {
  return ConfigurationSnapshot.create(
    crypto.randomUUID(),
    versionNumber,
    SnapshotType.create('manual_import'),
    Checksum.create('a'.repeat(64)),
    isActive,
    makePayload(bypassEntries),
    'test snapshot',
    new Date('2026-06-05T10:00:00.000Z'),
    'user-1',
  );
}

function makePayload(bypassEntries: SslBypassEntry[]): ConfigSnapshotPayload {
  return {
    bundle: {
      rules: { items: [] },
      zones: { items: [] },
      zone_interfaces: { items: [] },
      zone_pairs: { items: [] },
      nat_rules: { items: [] },
      dns_blacklist: { items: [] },
      ssl_bypass_list: { items: bypassEntries },
      ips_signatures: { items: [] },
      ips_config: null,
      ml_model: null,
      firewall_certificates: { items: [] },
      tls_inspection_policy: DEFAULT_TLS_INSPECTION_POLICY,
      identity_config: emptyIdentityConfigPayload(),
      dns_inspection_config: null,
      users: { items: [] },
    },
  };
}
