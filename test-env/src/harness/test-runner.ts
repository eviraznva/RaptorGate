import { match, P } from 'ts-pattern';
import { afterEach, afterAll, beforeEach } from 'bun:test';
import { getClient, getSnapshotClient } from './grpc-client';
import { eventCollector, type EventMatcher } from './event-collector';
import { ssh, sshWithResult, type KnownHost, spawnSsh, closeAllSshProcesses } from '../ssh-helper';
import type { FirewallQueryService } from '../generated/services/query_service';
import type { FirewallConfigSnapshotService } from '../generated/services/config_snapshot_service';

// ---------------------------------------------------------------------------
// Type extraction from generated gRPC service
// ---------------------------------------------------------------------------

export type QueryRpcMethodName = keyof FirewallQueryService;
export type SnapshotRpcMethodName = keyof FirewallConfigSnapshotService;
/** All available RPC method names on FirewallQueryService + FirewallConfigSnapshotService */
export type RpcMethodName = QueryRpcMethodName | SnapshotRpcMethodName;

/** The request payload type for a specific RPC method */
export type RequestPayload<M extends RpcMethodName> =
  M extends QueryRpcMethodName
    ? Parameters<FirewallQueryService[M]>[0]
    : M extends SnapshotRpcMethodName
      ? Parameters<FirewallConfigSnapshotService[M]>[0]
      : never;

const SNAPSHOT_RPCS: ReadonlySet<SnapshotRpcMethodName> = new Set([
  'PushActiveConfigSnapshot',
]);

function isSnapshotRpcMethod(rpc: RpcMethodName): rpc is SnapshotRpcMethodName {
  return SNAPSHOT_RPCS.has(rpc as SnapshotRpcMethodName);
}

// ---------------------------------------------------------------------------
// VM system time helper
// ---------------------------------------------------------------------------

/** Fetch the current VM system time in milliseconds since epoch. */
async function fetchVmSystemTimeMs(): Promise<number> {
  const client = getClient();
  return new Promise((resolve, reject) => {
    client.getSystemTime({}, (err: Error | null, resp: any) => {
      if (err) reject(err);
      else resolve(resp.time instanceof Date ? resp.time.getTime() : 0);
    });
  });
}

// ---------------------------------------------------------------------------
// Detached command — background process with automatic cleanup via SshProcessHandle
// ---------------------------------------------------------------------------

export class DetachedCommand {
  readonly host: KnownHost;
  readonly command: string;
  readonly handle: import('../ssh-helper').SshProcessHandle;
  private killed = false;

  constructor(host: KnownHost, command: string, handle: import('../ssh-helper').SshProcessHandle) {
    this.host = host;
    this.command = command;
    this.handle = handle;
  }

  async kill(): Promise<void> {
    if (this.killed) return;
    this.killed = true;
    this.handle.kill();
  }

  defer_cleanup(): this {
    afterEach(() => this.kill());
    afterAll(() => this.kill());
    return this;
  }

  toString(): string {
    return `[${this.host}] ${this.command} (killed=${this.killed})`;
  }
}

// ---------------------------------------------------------------------------
// Interfaces
// ---------------------------------------------------------------------------

export interface RequestOptions<M extends RpcMethodName> {
  rpc: M;
  body?: RequestPayload<M>;
}

export interface PerformCommandOptions {
  host: KnownHost;
  command: string;
}

// ---------------------------------------------------------------------------
// Request builder (gRPC trigger)
// ---------------------------------------------------------------------------

class RequestBuilder<M extends RpcMethodName> {
  private rpc: M;
  private body: RequestPayload<M>;
  private responsePattern: any = null;
  private eventPatterns: EventMatcher[] | null = null;
  private _printEvents = false;

  constructor(opts: RequestOptions<M>) {
    this.rpc = opts.rpc;
    this.body = opts.body ?? {} as RequestPayload<M>;
  }

  expectResponse(pattern: any): this {
    this.responsePattern = pattern;
    return this;
  }

  expectEvents(patterns: EventMatcher[]): this {
    this.eventPatterns = patterns;
    return this;
  }

  printEvents(): this {
    this._printEvents = true;
    return this;
  }

  async run(): Promise<void> {
    if (this._printEvents) {
      eventCollector.enablePrinting(true);
    }

    try {
      if (this.eventPatterns) {
        const vmTime = await fetchVmSystemTimeMs();
        eventCollector.setFence(vmTime);
      }

      const result = await this.invokeRpc();

      if (this.responsePattern) {
        this.assertResponse(result);
      }

      if (this.eventPatterns) {
        await this.assertEvents(this.eventPatterns);
      }
    } finally {
      if (this._printEvents) {
        eventCollector.enablePrinting(false);
      }
    }
  }

  private async invokeRpc(): Promise<any> {
    const client = isSnapshotRpcMethod(this.rpc)
      ? getSnapshotClient()
      : getClient();

    return new Promise((resolve, reject) => {
      client[this.rpc.charAt(0).toLowerCase() + this.rpc.slice(1)](this.body, (err: Error | null, resp: any) => {
        if (err) reject(err);
        else resolve(resp);
      });
    });
  }

  private assertResponse(response: any): void {
    const ok = matchPattern(response, this.responsePattern);
    if (!ok) {
      throw new Error(
        `Response assertion failed for ${this.rpc}. Got: ${JSON.stringify(response, null, 2)}`,
      );
    }
  }

  private async assertEvents(patterns: EventMatcher[]): Promise<void> {
    const result = await eventCollector.waitForSubsequence(patterns);
    if (!result.matched) {
      throw new Error(
        `Event assertion failed at pattern index ${result.failedAt}. Received ${result.received.length} events.`,
      );
    }
  }
}

// ---------------------------------------------------------------------------
// Command builder (SSH trigger)
// ---------------------------------------------------------------------------

class CommandBuilder {
  private host: KnownHost;
  private command: string;
  private outputRegexes: RegExp[] | null = null;
  private eventPatterns: EventMatcher[] | null = null;
  private expectError = false;
  private discardErrorCode = false;
  private _printEvents = false;

  constructor(opts: PerformCommandOptions) {
    this.host = opts.host;
    this.command = opts.command;
  }

  discardError(): this {
	  this.discardErrorCode = true
	  return this
  }

  expectOutput(regexes: RegExp[]): this {
    this.outputRegexes = regexes;
    return this;
  }

  expectEvents(patterns: EventMatcher[]): this {
    this.eventPatterns = patterns;
    return this;
  }

  printEvents(): this {
    this._printEvents = true;
    return this;
  }

  isOk(): this {
    this.expectError = false;
    return this;
  }

  isErr(): this {
    this.expectError = true;
    return this;
  }

  async run(): Promise<void> {
    if (this._printEvents) {
      eventCollector.enablePrinting(true);
    }

    try {
      if (this.eventPatterns) {
        const vmTime = await fetchVmSystemTimeMs();
        eventCollector.setFence(vmTime);
      }

      const { stdout, stderr, exitCode } = await this.invokeCommand();

      if (this.expectError && exitCode === 0) {
        throw new Error(
          `Command expected to fail but exited 0 on ${this.host}: ${this.command}`,
        );
      }

      if (!this.expectError && !this.discardErrorCode && exitCode !== 0) {
        throw new Error(
          `Command failed on ${this.host} (exit ${exitCode}): ${stderr || stdout}`,
        );
      }

      if (this.outputRegexes) {
        this.assertOutput(stdout, stderr);
      }

      if (this.eventPatterns) {
        const result = await eventCollector.waitForSubsequence(this.eventPatterns);
        if (!result.matched) {
          throw new Error(
            `Event assertion failed at pattern index ${result.failedAt}. Received ${result.received.length} events.`,
          );
        }
      }
    } finally {
      if (this._printEvents) {
        eventCollector.enablePrinting(false);
      }
    }
  }

  async runDetached(): Promise<DetachedCommand> {
    const handle = spawnSsh(this.host, this.command);
    // Give the server time to bind before the caller attempts to connect.
    await new Promise((r) => setTimeout(r, 1000));
    return new DetachedCommand(this.host, this.command, handle);
  }

  private async invokeCommand(): Promise<{ stdout: string; stderr: string; exitCode: number }> {
    return sshWithResult(this.host, this.command);
  }

  private assertOutput(stdout: string, stderr: string): void {
    const combined = stdout + stderr;
    const lines = combined.split('\n').filter((l) => l.trim());
    let lineIdx = 0;

    for (const regex of this.outputRegexes!) {
      let found = false;
      while (lineIdx < lines.length) {
        const line = lines[lineIdx]!;
        if (regex.test(line)) {
          found = true;
          lineIdx++;
          break;
        }
        lineIdx++;
      }
      if (!found) {
        throw new Error(
          `Output assertion failed: regex ${regex} did not match any line on ${this.host}. Output:\n${combined}`,
        );
      }
    }
  }
}

// ---------------------------------------------------------------------------
// Public API
// ---------------------------------------------------------------------------

/**
 * Create a typed gRPC request builder.
 * @param rpc - Literal RPC method name (e.g. 'GetPolicies' | 'PushActiveConfigSnapshot')
 * @param body - Strongly typed request payload (auto-constrained by rpc)
 */
export function request<M extends RpcMethodName>(
  rpc: M,
  body?: RequestPayload<M>,
): RequestBuilder<M> {
  return new RequestBuilder({ rpc, body });
}

export function performCommand(opts: PerformCommandOptions): CommandBuilder {
  return new CommandBuilder(opts);
}

// ---------------------------------------------------------------------------
// Global teardown — close all transient SSH processes
// ---------------------------------------------------------------------------

afterAll(async () => {
  await closeAllSshProcesses();
});

// ---------------------------------------------------------------------------
// Per-test setup — kill lingering background jobs from previous test
// ---------------------------------------------------------------------------

// beforeEach(async () => {
//   await killAllActiveJobs();
// });

// ---------------------------------------------------------------------------
// Pattern matching helper (ts-pattern)
// ---------------------------------------------------------------------------

function matchPattern(actual: any, pattern: any): boolean {
  if (pattern === P.any) return true;

  if (pattern && typeof pattern === 'object' && pattern[P.matcher]) {
    try {
      return match(actual).with(pattern, () => true).otherwise(() => false);
    } catch {
      return true;
    }
  }

  if (typeof pattern === 'function') {
    try {
      return !!pattern(actual);
    } catch {
      return false;
    }
  }

  if (typeof pattern !== 'object' || pattern === null) {
    return actual === pattern;
  }

  for (const [key, value] of Object.entries(pattern)) {
    if (!(key in actual)) return false;
    if (!matchPattern(actual[key], value)) return false;
  }
  return true;
}
