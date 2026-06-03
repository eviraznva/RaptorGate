import { describe, expect, it, jest } from 'bun:test';
import { IdentityConfiguration } from '../../../domain/entities/identity-configuration.entity.js';
import { Mutex } from '../json/file-mutex.js';
import { FileStore } from '../json/file-store.js';
import { JsonIdentityConfigRepository } from './json-identity-config.repository.js';

describe('JsonIdentityConfigRepository', () => {
  it('returns an empty identity config when the file is missing', async () => {
    const fileStore = {
      readJsonOrDefault: jest.fn(async (_path: string, fallback: unknown) => fallback),
      writeJsonAtomic: jest.fn(),
    } as unknown as FileStore;
    const mutex = {
      runExclusive: jest.fn(async (fn: () => Promise<void>) => fn()),
    } as unknown as Mutex;
    const repository = new JsonIdentityConfigRepository(fileStore, mutex);

    const config = await repository.find();

    expect(config.getRadiusServerProfiles()).toEqual([]);
    expect(config.getLdapServerProfiles()).toEqual([]);
    expect(config.getAuthenticationProfiles()).toEqual([]);
    expect(config.getSettings().getPortalAuthenticationProfileId()).toBeNull();
  });

  it('does not seed from env while reading a missing config file', async () => {
    const fileStore = {
      readJsonOrDefault: jest.fn(async (_path: string, fallback: unknown) => fallback),
      writeJsonAtomic: jest.fn(),
    } as unknown as FileStore;
    const mutex = {
      runExclusive: jest.fn(async (fn: () => Promise<void>) => fn()),
    } as unknown as Mutex;
    const repository = new JsonIdentityConfigRepository(fileStore, mutex);

    const config = await repository.find();

    expect(config.getRadiusServerProfiles()).toEqual([]);
    expect(fileStore.writeJsonAtomic).not.toHaveBeenCalled();
  });

  it('overwrites the identity config file with a strict record', async () => {
    const fileStore = {
      readJsonOrDefault: jest.fn(),
      writeJsonAtomic: jest.fn(),
    } as unknown as FileStore;
    const mutex = {
      runExclusive: jest.fn(async (fn: () => Promise<void>) => fn()),
    } as unknown as Mutex;
    const repository = new JsonIdentityConfigRepository(fileStore, mutex);

    await repository.overwrite(IdentityConfiguration.empty());

    expect(fileStore.writeJsonAtomic).toHaveBeenCalledWith(
      expect.stringContaining('identity-config.json'),
      {
        radius_server_profiles: { items: [] },
        ldap_server_profiles: { items: [] },
        authentication_profiles: { items: [] },
        authentication_sequences: { items: [] },
        identity_groups: { items: [] },
        settings: {
          portalAuthenticationProfileId: null,
          adminAuthenticationProfileId: null,
          portalListener: {
            enabled: false,
            interfaceName: null,
            zoneId: null,
            bindAddress: null,
            bindPort: 443,
          },
          updatedAt: null,
          updatedBy: null,
        },
      },
    );
  });
});
