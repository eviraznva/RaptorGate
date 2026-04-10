import { spawn } from 'node:child_process';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { existsSync } from 'node:fs';

const __dirname = path.dirname(fileURLToPath(import.meta.url));
export const REPO_ROOT = path.resolve(__dirname, '../..');
export const VAGRANT_DIR = path.resolve(REPO_ROOT, 'vagrant');
export const SSH_CONFIG_PATH = '/tmp/r1-ssh-config.txt';
export const VM_NAME = 'r1';

// ---------------------------------------------------------------------------
// Internal runner
// ---------------------------------------------------------------------------

function run(
  cmd: string,
  args: string[],
  opts: { cwd?: string; stdin?: 'inherit'; timeout?: number } = {},
): Promise<{ stdout: string; stderr: string; exitCode: number }> {
  return new Promise((resolve, reject) => {
    const timeout = opts.timeout ?? 30_000;
    const proc = spawn(cmd, args, {
      cwd: opts.cwd,
      shell: false,
      stdio: opts.stdin === 'inherit' ? ['inherit', 'pipe', 'pipe'] : ['ignore', 'pipe', 'pipe'],
    });
    let stdout = '';
    let stderr = '';
    let settled = false;
    const settle = (value: { stdout: string; stderr: string; exitCode: number }) => {
      if (settled) return;
      settled = true;
      clearTimeout(timer);
      resolve(value);
    };
    const timer = setTimeout(() => {
      proc.kill('SIGTERM');
      settle({ stdout, stderr, exitCode: 1 });
    }, timeout);
    proc.stdout.on('data', (d) => { stdout += d; });
    proc.stderr.on('data', (d) => { stderr += d; });
    proc.on('error', (err) => { clearTimeout(timer); reject(err); });
    proc.on('close', (code) => {
      settle({ stdout, stderr, exitCode: code ?? 1 });
    });
  });
}

// Expose run() for callers that need raw commands (e.g. vagrant status, vagrant ssh-config)
export { run };

// ---------------------------------------------------------------------------
// vagrant ssh wrapper
// ---------------------------------------------------------------------------

export async function vagrant_ssh(
  command: string,
): Promise<{ stdout: string; stderr: string }> {
  const { stdout, stderr, exitCode } = await run('vagrant', ['ssh', VM_NAME, '-c', command], {
    cwd: VAGRANT_DIR,
  });
  if (exitCode !== 0) {
    throw new Error(`vagrant ssh failed (exit ${exitCode}):\n${stderr || stdout}`);
  }
  return { stdout, stderr };
}

// ---------------------------------------------------------------------------
// ssh wrapper (uses pre-generated config)
// ---------------------------------------------------------------------------

export async function ssh(
  command: string,
): Promise<{ stdout: string; stderr: string }> {
  if (!existsSync(SSH_CONFIG_PATH)) {
    throw new Error(`SSH config not found at ${SSH_CONFIG_PATH}. Run vagrant ssh-config first.`);
  }

  const { stdout, stderr, exitCode } = await run('ssh', [
    '-F', SSH_CONFIG_PATH,
    '-o', 'BatchMode=yes',
    '-o', 'ConnectTimeout=10',
    VM_NAME,
    command,
  ]);
  if (exitCode !== 0) {
    throw new Error(`ssh failed (exit ${exitCode}):\n${stderr || stdout}`);
  }
  return { stdout, stderr };
}
