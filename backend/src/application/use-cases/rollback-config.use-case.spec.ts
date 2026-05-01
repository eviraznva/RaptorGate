import { jest } from '@jest/globals';
import { ConfigurationSnapshot } from '../../domain/entities/configuration-snapshot.entity.js';
import { Checksum } from '../../domain/value-objects/checksum.vo.js';
import { SnapshotType } from '../../domain/value-objects/snapshot-type.vo.js';
import { RollbackConfigUseCase } from './rollback-config.use-case.js';

describe('RollbackConfigUseCase identity config compatibility', () => {
  it('rolls back legacy snapshots without identity_config as empty identity config', async () => {
    const legacyPayload = {
      bundle: {
        rules: { items: [] },
        zones: { items: [] },
        zone_interfaces: { items: [] },
        zone_pairs: { items: [] },
        nat_rules: { items: [] },
        dns_blacklist: { items: [] },
        ssl_bypass_list: { items: [] },
        ips_signatures: { items: [] },
        ml_model: null,
        firewall_certificates: { items: [] },
        users: { items: [] },
      },
    };
    const snapshot = ConfigurationSnapshot.create(
      '00000000-0000-4000-8000-000000000010',
      1,
      SnapshotType.create('manual_import'),
      Checksum.create('checksum'),
      true,
      legacyPayload,
      null,
      new Date('2026-04-30T10:00:00.000Z'),
      '00000000-0000-4000-8000-000000000001',
    );
    const identityConfigRepository = {
      overwrite: jest.fn(async () => undefined),
    };
    const identitySecretReferenceValidator = {
      validateActiveConfig: jest.fn(async () => undefined),
    };
    const useCase = new RollbackConfigUseCase(
      { findById: jest.fn(async () => snapshot) } as any,
      { overwriteAll: jest.fn(async () => undefined) } as any,
      { overwriteAll: jest.fn(async () => undefined) } as any,
      { overwriteAll: jest.fn(async () => undefined) } as any,
      { overwriteAll: jest.fn(async () => undefined) } as any,
      { overwriteAll: jest.fn(async () => undefined) } as any,
      { overwriteAll: jest.fn(async () => undefined) } as any,
      { overwriteAll: jest.fn(async () => undefined) } as any,
      identityConfigRepository as any,
      identitySecretReferenceValidator as any,
      { pushActiveConfigSnapshot: jest.fn(async () => undefined) } as any,
    );

    await useCase.execute({ id: snapshot.getId() });

    expect(identityConfigRepository.overwrite).toHaveBeenCalledTimes(1);
    const config = (identityConfigRepository.overwrite as any).mock.calls[0][0];
    expect(config.getRadiusServerProfiles()).toEqual([]);
    expect(config.getSettings().getPortalAuthenticationProfileId()).toBeNull();
    expect(identitySecretReferenceValidator.validateActiveConfig).toHaveBeenCalledWith(config);
  });
});
