import { match, P } from 'ts-pattern';
import { afterEach, afterAll } from 'bun:test';
import { getClient } from './grpc-client';
import { eventCollector, type EventMatcher } from './event-collector';
import { ssh, sshWithResult, sshDetached, sshKill, type KnownHost } from '../ssh-helper';
import type { FirewallQueryService } from '../generated/services/query_service';

const DEFAULT_TIMEOUT = 5_000;

// ---------------------------------------------------------------------------
// Type extraction from generated gRPC service
// ---------------------------------------------------------------------------

/** All available RPC method names on FirewallQueryService */
export type RpcMethodName = keyof FirewallQueryService;

/** The request payload type for a specific RPC method */
export type RequestPayload<M extends RpcMethodName> = Parameters<FirewallQueryService[M]>[0];

// ---------------------------------------------------------------------------
// Detached command — background process with automatic cleanup
// ---------------------------------------------------------------------------

export class DetachedCommand {
  readonly host: KnownHost;
  readonly command: string;
  readonly pid: number;
  private killed = false;

  constructor(host: KnownHost, command: string, pid: number) {
    this.host = host;
    this.command = command;
    this.pid = pid;
  }

  async kill(): Promise<void> {
    if (this.killed) return;
    this.killed = true;
    await sshKill(this.host, this.pid);
  }

  cleanup(): this {
    afterEach(() => this.kill());
    afterAll(() => this.kill());
    return this;
  }

  toString(): string {
    return `[${this.host}] ${this.command} (pid=${this.pid}, killed=${this.killed})`;
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

export interface RunOptions {
  timeout?: number;
}

// ---------------------------------------------------------------------------
// Request builder (gRPC trigger)
// ---------------------------------------------------------------------------

class RequestBuilder<M extends RpcMethodName> {
  private rpc: M;
  private body: RequestPayload<M>;
  private responsePattern: any = null;
  private eventPatterns: EventMatcher[] | null = null;

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

  async run(options?: RunOptions): Promise<void> {
    const timeout = options?.timeout ?? DEFAULT_TIMEOUT;
    const client = getClient();

    const result = await this.invokeRpc(client, timeout);

    if (this.responsePattern) {
      this.assertResponse(result, timeout);
    }

    if (this.eventPatterns) {
      await this.assertEvents(this.eventPatterns, timeout);
    }
  }

  private async invokeRpc(client: any, timeout: number): Promise<any> {
    return new Promise((resolve, reject) => {
      const timer = setTimeout(() => reject(new Error(`RPC ${this.rpc} timed out after ${timeout}ms`)), timeout);
      client[this.rpc.charAt(0).toLowerCase() + this.rpc.slice(1)](this.body, (err: Error | null, resp: any) => {
        clearTimeout(timer);
        if (err) reject(err);
        else resolve(resp);
      });
    });
  }

  private assertResponse(response: any, _timeout: number): void {
    const ok = matchPattern(response, this.responsePattern);
    if (!ok) {
      throw new Error(
        `Response assertion failed for ${this.rpc}. Got: ${JSON.stringify(response, null, 2)}`,
      );
    }
  }

  private async assertEvents(patterns: EventMatcher[], timeout: number): Promise<void> {
    eventCollector.setFence();
    const result = await eventCollector.waitForSubsequence(patterns, timeout);
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

  constructor(opts: PerformCommandOptions) {
    this.host = opts.host;
    this.command = opts.command;
  }

  expectOutput(regexes: RegExp[]): this {
    this.outputRegexes = regexes;
    return this;
  }

  expectEvents(patterns: EventMatcher[]): this {
    this.eventPatterns = patterns;
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

  async run(options?: RunOptions): Promise<void> {
    const timeout = options?.timeout ?? DEFAULT_TIMEOUT;

    if (this.eventPatterns) {
      eventCollector.setFence();
    }

    const { stdout, stderr, exitCode } = await this.invokeCommand(timeout);

    if (this.expectError && exitCode === 0) {
      throw new Error(
        `Command expected to fail but exited 0 on ${this.host}: ${this.command}`,
      );
    }

    if (!this.expectError && exitCode !== 0) {
      throw new Error(
        `Command failed on ${this.host} (exit ${exitCode}): ${stderr || stdout}`,
      );
    }

    if (this.outputRegexes) {
      this.assertOutput(stdout, stderr);
    }

    if (this.eventPatterns) {
      const result = await eventCollector.waitForSubsequence(this.eventPatterns, timeout);
      if (!result.matched) {
        throw new Error(
          `Event assertion failed at pattern index ${result.failedAt}. Received ${result.received.length} events.`,
        );
      }
    }
  }

  async runDetached(): Promise<DetachedCommand> {
    const pid = await sshDetached(this.host, this.command);
    return new DetachedCommand(this.host, this.command, pid);
  }

  private async invokeCommand(timeout: number): Promise<{ stdout: string; stderr: string; exitCode: number }> {
    return Promise.race([
      sshWithResult(this.host, this.command),
      new Promise<{ stdout: string; stderr: string; exitCode: number }>((_, reject) =>
        setTimeout(() => reject(new Error(`Command timed out after ${timeout}ms: ${this.command}`)), timeout),
      ),
    ]);
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
 * @param rpc - Literal RPC method name (e.g. 'SwapPolicies')
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
