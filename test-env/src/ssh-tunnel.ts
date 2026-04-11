import { spawn, type ChildProcess } from 'node:child_process';
import * as grpc from '@grpc/grpc-js';
import * as protoLoader from '@grpc/proto-loader';
import path from 'node:path';
import { run, SSH_CONFIG_PATH, VAGRANT_DIR, VM_NAME, vagrant_ssh } from './ssh-helper';

const TUNNEL_REMOTE_SOCKET = '/resources/ngfw/sockets/event.sock';
const TUNNEL_LOCAL_PORT = 50052;
const QUERY_LOCAL_SOCKET = '/tmp/query.sock';
const QUERY_REMOTE_SOCKET = '/resources/ngfw/sockets/query.sock';
const POLL_INTERVAL_MS = 5_000;

// ---------------------------------------------------------------------------
// Generated proto loading (shared with server.ts logic)
// ---------------------------------------------------------------------------

const PROTO_ROOT = path.resolve(__dirname, '../../proto');
const PROTO_FILES = [
  path.join(PROTO_ROOT, 'services', 'event_service.proto'),
  path.join(PROTO_ROOT, 'services', 'query_service.proto'),
  path.join(PROTO_ROOT, 'events', 'firewall_events.proto'),
  path.join(PROTO_ROOT, 'common', 'common.proto'),
  path.join(PROTO_ROOT, 'config', 'config_models.proto'),
];

const LOADER_OPTIONS = {
  keepCase: true,
  longs: String,
  enums: String,
  defaults: true,
  oneofs: true,
  includeDirs: [PROTO_ROOT],
};

const packageDef = protoLoader.loadSync(PROTO_FILES, LOADER_OPTIONS);
const proto = grpc.loadPackageDefinition(packageDef) as any;

const QueryServiceClient = proto.raptorgate.services.FirewallQueryService;

// ---------------------------------------------------------------------------
// Ready callback interface
// ---------------------------------------------------------------------------

export interface TunnelReadyContext {
  /** gRPC server for BackendEventService (already bound, firewalls connect here) */
  eventServer: grpc.Server;
  /** gRPC client for FirewallQueryService (connected to forwarded query.sock) */
  queryClient: any; // grpc.Client subclass — methods discovered at runtime
}

export interface SshTunnelOptions {
  onReady: (ctx: TunnelReadyContext) => void;
}

// ---------------------------------------------------------------------------
// VM status
// ---------------------------------------------------------------------------

async function isVmRunning(): Promise<boolean> {
  try {
    const { stdout, exitCode } = await run('vagrant', ['status', VM_NAME], { cwd: VAGRANT_DIR });
    if (exitCode !== 0) return false;
    return /^.*running\s+\(libvirt\)/m.test(stdout);
  } catch {
    return false;
  }
}

// ---------------------------------------------------------------------------
// SSH config generation
// ---------------------------------------------------------------------------

async function generateSshConfig(): Promise<boolean> {
  try {
    const { stdout, exitCode } = await run('vagrant', ['ssh-config', VM_NAME], { cwd: VAGRANT_DIR });
    if (exitCode !== 0 || !stdout.includes('Host ')) return false;

    const { writeFileSync } = await import('node:fs');
    const configStart = stdout.indexOf('Host ');
    writeFileSync(SSH_CONFIG_PATH, stdout.slice(configStart));
    return true;
  } catch {
    return false;
  }
}

// ---------------------------------------------------------------------------
// ngfw service check
// ---------------------------------------------------------------------------

async function isNgfwActive(): Promise<boolean> {
  try {
    const { stdout } = await vagrant_ssh('systemctl is-active ngfw');
    return stdout.trim() === 'active';
  } catch {
    return false;
  }
}

// ---------------------------------------------------------------------------
// Remote socket cleanup
// ---------------------------------------------------------------------------

async function removeRemoteSocket(socketPath: string): Promise<void> {
  await vagrant_ssh(`rm -f ${socketPath}`);
  console.log('[ssh-tunnel] Cleaned up stale remote socket:', socketPath);
}

// ---------------------------------------------------------------------------
// SSH tunnel management (generic)
// ---------------------------------------------------------------------------

function startSshTunnelProcess(
  mode: '-R' | '-L',
  localSpec: string,
  remoteSpec: string,
): ChildProcess {
  const proc = spawn(
    'ssh',
    [
      '-F', SSH_CONFIG_PATH,
      '-o', 'StreamLocalBindUnlink=yes',
      '-o', 'ServerAliveInterval=15',
      '-o', 'ServerAliveCountMax=3',
      mode,
      mode === '-R' ? `${remoteSpec}:localhost:${localSpec}` : `${localSpec}:${remoteSpec}`,
      VM_NAME,
      '-N',
    ],
    { stdio: ['ignore', 'pipe', 'pipe'] },
  );

  proc.stdout?.on('data', (d) => process.stdout.write(`[tunnel] ${d}`));
  proc.stderr?.on('data', (d) => process.stderr.write(`[tunnel] ${d}`));

  return proc;
}

function killTunnelProcess(proc: ChildProcess | null): Promise<void> {
  return new Promise((resolve) => {
    if (!proc) { resolve(); return; }
    proc.on('close', () => { resolve(); });
    proc.kill('SIGTERM');
    setTimeout(() => { proc.kill('SIGKILL'); }, 3000);
  });
}

// ---------------------------------------------------------------------------
// Wait helper
// ---------------------------------------------------------------------------

async function waitFor(predicate: () => Promise<boolean>, label: string): Promise<void> {
  let attempt = 0;
  while (true) {
    attempt++;
    const ok = await predicate();
    if (ok) {
      console.log(`[ssh-tunnel] ${label} — OK (attempt ${attempt})`);
      return;
    }
    if (attempt === 1) {
      console.log(`[ssh-tunnel] Waiting for ${label} ...`);
    }
    await new Promise((r) => setTimeout(r, POLL_INTERVAL_MS));
  }
}

// ---------------------------------------------------------------------------
// Event tunnel loop (reverse -R)
// ---------------------------------------------------------------------------

function createEventTunnelLoop(
  eventServer: grpc.Server,
  onReady: () => void,
  onDisconnect: () => void,
): () => Promise<void> {
  let eventTunnelProc: ChildProcess | null = null;

  async function loop(): Promise<void> {
    while (true) {
      await waitFor(isVmRunning, `${VM_NAME} VM to be running`);
      await waitFor(generateSshConfig, 'SSH config generation');
      await waitFor(isNgfwActive, 'ngfw service to be active');
      await removeRemoteSocket(TUNNEL_REMOTE_SOCKET);

      console.log('[event-tunnel] Establishing reverse SSH tunnel ...');
      eventTunnelProc = startSshTunnelProcess('-R', String(TUNNEL_LOCAL_PORT), TUNNEL_REMOTE_SOCKET);

      await new Promise<void>((resolve) => {
        if (!eventTunnelProc) { resolve(); return; }

        eventTunnelProc.on('error', (err) => {
          console.error(`[event-tunnel] Tunnel process error: ${err.message}`);
        });

        eventTunnelProc.on('close', (code, signal) => {
          console.log(`[event-tunnel] Tunnel closed (code=${code}, signal=${signal}). Reconnecting ...`);
          resolve();
        });

        // Tunnel is up — signal ready
        onReady();
        console.log('[event-tunnel] Tunnel established');
      });

      await killTunnelProcess(eventTunnelProc);
      eventTunnelProc = null;
      onDisconnect();
      await new Promise((r) => setTimeout(r, POLL_INTERVAL_MS));
    }
  }

  return loop;
}

// ---------------------------------------------------------------------------
// Query tunnel loop (forward -L) + gRPC client
// ---------------------------------------------------------------------------

function createQueryClientLoop(
  onReady: () => void,
  onDisconnect: () => void,
): () => Promise<void> {
  let queryTunnelProc: ChildProcess | null = null;

  async function cleanupLocalSocket(): Promise<void> {
    try {
      const { unlinkSync, existsSync } = await import('node:fs');
      if (existsSync(QUERY_LOCAL_SOCKET)) {
        unlinkSync(QUERY_LOCAL_SOCKET);
      }
    } catch { /* ignore */ }
  }

  async function loop(): Promise<void> {
    while (true) {
      await waitFor(isVmRunning, `${VM_NAME} VM to be running`);
      await waitFor(generateSshConfig, 'SSH config generation');
      await waitFor(isNgfwActive, 'ngfw service to be active');
      await cleanupLocalSocket();

      console.log('[query-tunnel] Establishing forward SSH tunnel ...');
      queryTunnelProc = startSshTunnelProcess('-L', QUERY_LOCAL_SOCKET, QUERY_REMOTE_SOCKET);

      // Wait a moment for the socket file to appear
      await new Promise((r) => setTimeout(r, 1000));

      let queryClient: any = null;
      try {
        queryClient = new QueryServiceClient(
          `unix:${QUERY_LOCAL_SOCKET}`,
          grpc.credentials.createInsecure(),
        );
      } catch (err) {
        console.error('[query-tunnel] Failed to create gRPC client:', err);
        await killTunnelProcess(queryTunnelProc);
        queryTunnelProc = null;
        onDisconnect();
        await new Promise((r) => setTimeout(r, POLL_INTERVAL_MS));
        continue;
      }

      await new Promise<void>((resolve) => {
        if (!queryTunnelProc) { resolve(); return; }

        queryTunnelProc.on('error', (err) => {
          console.error(`[query-tunnel] Tunnel process error: ${err.message}`);
        });

        queryTunnelProc.on('close', (code, signal) => {
          console.log(`[query-tunnel] Tunnel closed (code=${code}, signal=${signal}). Reconnecting ...`);
          resolve();
        });

        // gRPC client is connected — signal ready
        onReady();
        console.log('[query-tunnel] Tunnel established, gRPC client connected');
      });

      await killTunnelProcess(queryTunnelProc);
      queryTunnelProc = null;
      onDisconnect();
      await new Promise((r) => setTimeout(r, POLL_INTERVAL_MS));
    }
  }

  return loop;
}

// ---------------------------------------------------------------------------
// Main orchestrator
// ---------------------------------------------------------------------------

export function startSshTunnel(eventServer: grpc.Server, opts: SshTunnelOptions): void {
  let eventReady = false;
  let queryReady = false;
  let hasFired = false;

  function checkReady() {
    if (eventReady && queryReady && !hasFired) {
      hasFired = true;
      console.log('[ssh-tunnel] Both event server and query client are connected — ready!');

      const queryClient = new (proto.raptorgate.services.FirewallQueryService)(
        `unix:${QUERY_LOCAL_SOCKET}`,
        grpc.credentials.createInsecure(),
      );

      opts.onReady({ eventServer, queryClient });
    }
  }

  // Event tunnel
  const eventLoop = createEventTunnelLoop(
    eventServer,
    () => { eventReady = true; checkReady(); },
    () => { eventReady = false; hasFired = false; },
  );
  eventLoop().catch((err) => console.error('[event-tunnel] Fatal:', err));

  // Query tunnel
  const queryLoop = createQueryClientLoop(
    () => { queryReady = true; checkReady(); },
    () => { queryReady = false; hasFired = false; },
  );
  queryLoop().catch((err) => console.error('[query-tunnel] Fatal:', err));
}
