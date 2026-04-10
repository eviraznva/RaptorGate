import { spawn, type ChildProcess } from 'node:child_process';
import { run, SSH_CONFIG_PATH, VAGRANT_DIR, VM_NAME, vagrant_ssh } from './ssh-helper';

const TUNNEL_REMOTE_SOCKET = '/resources/ngfw/sockets/event.sock';
const TUNNEL_LOCAL_PORT = 50052;
const POLL_INTERVAL_MS = 5_000;

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

    // Extract just the SSH config block (strip any progress/info lines from stderr)
    const configStart = stdout.indexOf('Host ');
    const { writeFileSync } = await import('node:fs');
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

async function removeRemoteSocket(): Promise<void> {
  await vagrant_ssh(`rm -f ${TUNNEL_REMOTE_SOCKET}`);
  console.log('[ssh-tunnel] Cleaned up stale remote socket');
}

// ---------------------------------------------------------------------------
// SSH tunnel management
// ---------------------------------------------------------------------------

let tunnelProc: ChildProcess | null = null;

function killTunnel(): Promise<void> {
  return new Promise((resolve) => {
    if (!tunnelProc) { resolve(); return; }
    tunnelProc.on('close', () => { resolve(); });
    tunnelProc.kill('SIGTERM');
    // Force-kill after 3 s if it refuses
    setTimeout(() => { tunnelProc?.kill('SIGKILL'); }, 3000);
    tunnelProc = null;
  });
}

function startTunnelProcess(): ChildProcess {
  const proc = spawn(
    'ssh',
    [
      '-F', SSH_CONFIG_PATH,
      '-o', 'StreamLocalBindUnlink=yes',
      '-o', 'ServerAliveInterval=15',
      '-o', 'ServerAliveCountMax=3',
      '-R', `${TUNNEL_REMOTE_SOCKET}:localhost:${TUNNEL_LOCAL_PORT}`,
      VM_NAME,
      '-N',
    ],
    { stdio: ['ignore', 'pipe', 'pipe'] },
  );

  proc.stdout?.on('data', (d) => process.stdout.write(`[tunnel] ${d}`));
  proc.stderr?.on('data', (d) => process.stderr.write(`[tunnel] ${d}`));

  return proc;
}

// ---------------------------------------------------------------------------
// Main loop
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

async function tunnelLoop(): Promise<void> {
  while (true) {
    // 1. Wait for VM to be running
    await waitFor(isVmRunning, `${VM_NAME} VM to be running`);

    // 2. Generate SSH config
    await waitFor(generateSshConfig, 'SSH config generation');

    // 3. Wait for ngfw service
    await waitFor(isNgfwActive, 'ngfw service to be active');

    // 4. Clean up stale socket on the VM (required for reverse tunnel to bind)
    await removeRemoteSocket();

    // 5. Start tunnel
    console.log('[ssh-tunnel] Establishing reverse SSH tunnel ...');
    tunnelProc = startTunnelProcess();

    await new Promise<void>((resolve) => {
      if (!tunnelProc) { resolve(); return; }

      tunnelProc.on('error', (err) => {
        console.error(`[ssh-tunnel] Tunnel process error: ${err.message}`);
      });

      tunnelProc.on('close', (code, signal) => {
        console.log(`[ssh-tunnel] Tunnel closed (code=${code}, signal=${signal}). Reconnecting ...`);
        resolve();
      });

      console.log('[ssh-tunnel] Tunnel established');
    });

    await killTunnel();
    tunnelProc = null;

    // Small back-off before re-evaluating
    await new Promise((r) => setTimeout(r, POLL_INTERVAL_MS));
  }
}

export function startSshTunnel(): void {
  tunnelLoop().catch((err) => {
    console.error('[ssh-tunnel] Fatal error:', err);
  });
}
