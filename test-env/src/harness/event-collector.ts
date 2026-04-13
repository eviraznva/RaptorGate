import { match, P } from 'ts-pattern';
import type { EventKind } from '../generated/events/firewall_events';

export type EventKindName = NonNullable<EventKind['item']>['$case'];

export interface EventMatcher {
  kind: EventKindName;
  match?: Record<string, unknown>;
}

export interface BufferedEvent {
  emittedAt?: { seconds: number | string; nanos: number };
  kind?: {
    item?: EventKindName;
    [key: string]: unknown;
  };
  [key: string]: unknown;
}

export interface WaitForResult {
  matched: boolean;
  received: BufferedEvent[];
  failedAt?: number;
}

export class EventCollector {
  private buffer: BufferedEvent[] = [];
  private fenceMs = 0;

  /**
   * Set a fence at the given VM timestamp (ms since epoch).
   * Only events emitted after this point will be considered.
   * The VM timestamp must come from `GetSystemTime` to avoid clock skew.
   */
  setFence(vmTimestampMs: number): void {
    this.fenceMs = vmTimestampMs;
  }

  push(event: any): void {
    this.buffer.push(event);
  }

  async waitForSubsequence(
    patterns: EventMatcher[],
  ): Promise<WaitForResult> {
    if (patterns.length === 0) {
      return { matched: true, received: [] };
    }

    let patternIdx = 0;

    while (true) {
      const relevant = this.buffer.filter((e) => this.isAfterFence(e));

      for (const event of relevant) {
        if (patternIdx >= patterns.length) break;

        const pattern = patterns[patternIdx]!;
        if (this.matchesEvent(event, pattern)) {
          patternIdx++;
        } else if (this.isOutOfOrder(event, patterns, patternIdx)) {
          return { matched: false, received: relevant, failedAt: patternIdx };
        }
      }

      if (patternIdx >= patterns.length) {
        return { matched: true, received: relevant };
      }

      await new Promise((r) => setTimeout(r, 100));
    }
  }

  private isAfterFence(event: BufferedEvent): boolean {
    if (!event.emittedAt) return false;
    const seconds =
      typeof event.emittedAt.seconds === 'string'
        ? parseInt(event.emittedAt.seconds, 10)
        : event.emittedAt.seconds;
    const eventMs = seconds * 1000 + (event.emittedAt.nanos ?? 0) / 1_000_000;
    return eventMs > this.fenceMs;
  }

  private matchesEvent(event: BufferedEvent, pattern: EventMatcher): boolean {
    const kindItem = event.kind?.item;
    if (kindItem !== pattern.kind) {
      return false;
    }

    if (!pattern.match) {
      return true;
    }

    const payload = this.extractPayload(event, pattern.kind);
    if (!payload) return false;

    try {
      return match(payload)
        .with(pattern.match as any, () => true)
        .otherwise(() => false);
    } catch {
      return this.shallowMatch(payload, pattern.match);
    }
  }

  private extractPayload(event: BufferedEvent, kind: EventKindName): Record<string, unknown> | null {
    if (!event.kind) return null;
    return (event.kind[kind] as Record<string, unknown> | undefined) ?? null;
  }

  private shallowMatch(
    actual: Record<string, unknown>,
    expected: Record<string, unknown>,
  ): boolean {
    for (const [key, value] of Object.entries(expected)) {
      if (!(key in actual)) return false;
      if (typeof value === 'object' && value !== null && typeof actual[key] === 'object') {
        if (!this.shallowMatch(actual[key] as any, value as any)) return false;
      } else if (actual[key] !== value) {
        return false;
      }
    }
    return true;
  }

  private isOutOfOrder(
    event: BufferedEvent,
    patterns: EventMatcher[],
    currentIdx: number,
  ): boolean {
    for (let i = currentIdx + 1; i < patterns.length; i++) {
      if (this.matchesEvent(event, patterns[i]!)) {
        return true;
      }
    }
    return false;
  }
}

export const eventCollector = new EventCollector();
