import { Test, type TestingModule } from '@nestjs/testing';
import { MicroserviceOptions, Transport } from '@nestjs/microservices';
import { type LoggerService, type LogLevel } from '@nestjs/common';
import { type ChildProcess, spawn } from 'node:child_process';
import { mkdtempSync, rmSync } from 'node:fs';
import { join, resolve } from 'node:path';
import { tmpdir } from 'node:os';
import { GrpcModule } from './grpc.module';
import { CONFIG_SNAPSHOT_REPOSITORY_TOKEN } from 'src/domain/repositories/config-snapshot.repository';
import { ConfigurationSnapshot } from 'src/domain/entities/configuration-snapshot.entity';
import { SnapshotType } from 'src/domain/value-objects/snapshot-type.vo';
import { Checksum } from 'src/domain/value-objects/checksum.vo';
import type { ConfigSnapshotPayload } from 'src/domain/value-objects/config-snapshot-payload.interface';

const runIntegration = process.env.RUN_FIREWALL_INTEGRATION === '1';
const describeIntegration = runIntegration ? describe : describe.skip;

const repoRoot = resolve(__dirname, '../../../../');
const firewallBinaryPath = join(repoRoot, 'target', 'debug', 'ngfw');

jest.setTimeout(30_000);

const TEST_PAYLOAD: ConfigSnapshotPayload = {
  section_versions: {
    rules: 1,
    zones: 1,
    zone_interfaces: 1,
    zone_pairs: 1,
    nat_rules: 1,
    dns_blacklist: 1,
    ssl_bypass_list: 1,
    ips_signatures: 1,
    ml_model: 1,
    certificates: 1,
    identity: 1,
  },
  bundle: {
    rules: { checksum: 'abc', items: [] },
    zones: { items: [] },
    zone_interfaces: { items: [] },
    zone_pairs: { items: [] },
    nat_rules: { items: [] },
    dns_blacklist: { items: [] },
    ssl_bypass_list: { items: [] },
    ips_signatures: { items: [] },
    ml_model: { id: 'ml-1', name: 'noop', artifact_path: '/dev/null', checksum: 'none' },
    firewall_certificates: { items: [] },
    identity: {
      user_groups: [],
      identity_users: [],
      user_group_members: [],
      user_sessions: [],
    },
  },
};

const TEST_CHECKSUM = 'a'.repeat(64);

const TEST_SNAPSHOT = ConfigurationSnapshot.create(
  '00000000-0000-0000-0000-000000000001',
  1,
  SnapshotType.create('manual_import'),
  Checksum.create(TEST_CHECKSUM),
  true,
  TEST_PAYLOAD,
  null,
  new Date(),
  '00000000-0000-0000-0000-000000000099',
);

class TestLogger implements LoggerService {
  readonly messages: string[] = [];

  log(message: unknown, ...optionalParams: unknown[]) {
    this.capture('LOG', message, optionalParams);
  }
  error(message: unknown, ...optionalParams: unknown[]) {
    this.capture('ERROR', message, optionalParams);
  }
  warn(message: unknown, ...optionalParams: unknown[]) {
    this.capture('WARN', message, optionalParams);
  }
  debug(message: unknown, ...optionalParams: unknown[]) {
    this.capture('DEBUG', message, optionalParams);
  }
  verbose(message: unknown, ...optionalParams: unknown[]) {
    this.capture('VERBOSE', message, optionalParams);
  }

  setLogLevels(_levels: LogLevel[]) {}

  private capture(level: string, message: unknown, params: unknown[]) {
    const context = params.length > 0 ? ` [${params[params.length - 1]}]` : '';
    this.messages.push(`${level}${context} ${message}`);
  }
}

describeIntegration('gRPC integration: firewall ↔ backend', () => {
  let app: ReturnType<TestingModule['createNestMicroservice']> extends Promise<infer T> ? T : never;
  let firewallProcess: ChildProcess | null = null;
  let runtimeDir: string;
  let firewallLogs = '';
  let testLogger: TestLogger;

  beforeAll(async () => {
    runtimeDir = mkdtempSync(join(tmpdir(), 'raptorgate-grpc-it-'));
    const backendSocketPath = join(runtimeDir, 'backend.sock');

    testLogger = new TestLogger();

    const moduleRef = await Test.createTestingModule({
      imports: [GrpcModule],
    })
      .overrideProvider(CONFIG_SNAPSHOT_REPOSITORY_TOKEN)
      .useValue({
        findActiveSnapshot: async () => TEST_SNAPSHOT,
      })
      .compile();

    app = await moduleRef.createNestMicroservice<MicroserviceOptions>({
      transport: Transport.GRPC,
      options: {
        package: ['raptorgate', 'raptorgate.config', 'raptorgate.events'],
        protoPath: join(repoRoot, 'proto', 'raptorgate.proto'),
        loader: { includeDirs: [join(repoRoot, 'proto')] },
        url: `unix://${backendSocketPath}`,
      },
    });

    app.useLogger(testLogger);
    await app.listen();

    firewallProcess = spawnFirewall(runtimeDir, backendSocketPath);

    await waitForFirewallLog('Config loaded, entering NORMAL mode', 15_000);

    // Give time for the immediate heartbeat + EventStream setup
    await delay(3_000);
  });

  afterAll(async () => {
    await stopFirewall();

    if (app) {
      await app.close();
    }

    rmSync(runtimeDir, { recursive: true, force: true });
  });

  it('should complete GetActiveConfig flow on startup', () => {
    const backendLogs = testLogger.messages.join('\n');

    // Backend should have logged the GetActiveConfig call with STARTUP reason
    expect(backendLogs).toContain('[GetActiveConfig]');
    expect(backendLogs).toMatch(/\[GetActiveConfig\].*reason=1/); // 1 = STARTUP

    // Firewall should have entered NORMAL mode
    expect(firewallLogs).toContain('Config loaded, entering NORMAL mode');
  });

  it('should establish EventStream and receive heartbeats', () => {
    const backendLogs = testLogger.messages.join('\n');

    expect(backendLogs).toContain('[EventStream] Firewall connected');
    expect(backendLogs).toContain('fw.heartbeat');
  });

  it('should follow correct bootstrap sequence', () => {
    const lines = firewallLogs.split('\n');

    const connectingIdx = lines.findIndex((l) =>
      l.includes('Connecting to backend'),
    );
    const fetchingIdx = lines.findIndex((l) =>
      l.includes('Connected to backend, fetching config'),
    );
    const normalIdx = lines.findIndex((l) =>
      l.includes('Config loaded, entering NORMAL mode'),
    );

    expect(connectingIdx).toBeGreaterThanOrEqual(0);
    expect(fetchingIdx).toBeGreaterThan(connectingIdx);
    expect(normalIdx).toBeGreaterThan(fetchingIdx);
  });

  // ── helpers ──────────────────────────────────────────────────────────

  function spawnFirewall(
    tmpRuntimeDir: string,
    backendSocketPath: string,
  ): ChildProcess {
    const child = spawn(firewallBinaryPath, [], {
      cwd: repoRoot,
      env: {
        ...process.env,
        DISABLE_DATA_PLANE: 'true',
        GRPC_SOCKET_PATH: backendSocketPath,
        CONTROL_PLANE_GRPC_SOCKET_PATH: join(
          tmpRuntimeDir,
          'control-plane.sock',
        ),
        REDB_SNAPSHOT_PATH: join(tmpRuntimeDir, 'snapshot.redb'),
        RAPTORGATE_PKI_DIR: join(tmpRuntimeDir, 'pki'),
        HEARTBEAT_INTERVAL_SECS: '2',
      },
      stdio: ['ignore', 'pipe', 'pipe'],
    });

    child.stdout?.on('data', (chunk: Buffer | string) => {
      firewallLogs += chunk.toString();
    });
    child.stderr?.on('data', (chunk: Buffer | string) => {
      firewallLogs += chunk.toString();
    });

    return child;
  }

  async function waitForFirewallLog(
    needle: string,
    timeoutMs: number,
  ): Promise<void> {
    const deadline = Date.now() + timeoutMs;

    while (Date.now() < deadline) {
      if (firewallProcess?.exitCode !== null) {
        throw new Error(
          `Firewall exited before "${needle}" appeared.\n${firewallLogs}`,
        );
      }

      if (firewallLogs.includes(needle)) {
        return;
      }

      await delay(200);
    }

    throw new Error(
      `Timed out (${timeoutMs}ms) waiting for firewall log: "${needle}"\n` +
        `--- Firewall logs ---\n${firewallLogs}\n` +
        `--- Backend logs ---\n${testLogger.messages.join('\n')}`,
    );
  }

  async function stopFirewall(): Promise<void> {
    if (!firewallProcess) {
      return;
    }

    const child = firewallProcess;
    firewallProcess = null;

    if (child.exitCode !== null) {
      child.stdout?.destroy();
      child.stderr?.destroy();
      return;
    }

    child.kill('SIGTERM');

    await Promise.race([
      new Promise<void>((resolveExit) => {
        child.once('exit', () => resolveExit());
      }),
      new Promise<void>((resolveTimeout) =>
        setTimeout(() => {
          if (child.exitCode === null) {
            child.kill('SIGKILL');
          }
          resolveTimeout();
        }, 3_000),
      ),
    ]);

    child.stdout?.destroy();
    child.stderr?.destroy();
  }

  function delay(ms: number): Promise<void> {
    return new Promise((resolve) => setTimeout(resolve, ms));
  }
});
