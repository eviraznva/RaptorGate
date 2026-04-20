import { beforeAll } from 'bun:test';
import { initializeHarness, waitForReady } from './setup';

initializeHarness();

beforeAll(async () => {
  await waitForReady();
}, { timeout: 120_000 });

export { request, performCommand, DetachedCommand } from './test-runner';
export { resetFirewallState } from './fixtures';
export { getClient, getSnapshotClient } from './grpc-client';
