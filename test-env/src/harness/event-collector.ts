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

  // Notification promise — wakes up waitForSubsequence on each push()
  private notify: (() => void) | null = null;
  private notifyPromise: Promise<void> | null = null;

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
    // Wake up exactly one waiting waitForSubsequence (if any)
    if (this.notify) {
      this.notify();
      this.notify = null;
    }
  }

  /** Return a promise that resolves on the next push(). */
  private awaitNewEvent(): Promise<void> {
    if (this.notifyPromise) {
      // Already have a pending notification — reuse it
      const p = this.notifyPromise;
      this.notifyPromise = null;
      return p;
    }
    return new Promise<void>((resolve) => {
      this.notify = resolve;
    });
  }

  async waitForSubsequence(
    patterns: EventMatcher[],
  ): Promise<WaitForResult> {
    if (patterns.length === 0) {
      return { matched: true, received: [] };
    }

    while (true) {
      const result = this.tryMatch(patterns);
      if (result.matched || result.terminated) {
        return result;
      }

      await this.awaitNewEvent();
    }
  }

  /**
   * Synchronous attempt to match patterns against the current buffer.
   * Returns immediately — does not wait for new events.
   */
  private tryMatch(patterns: EventMatcher[]): WaitForResult & { terminated: boolean } {
    let patternIdx = 0;
    const relevant = this.buffer.filter((e) => this.isAfterFence(e));

    for (const event of relevant) {
      if (patternIdx >= patterns.length) break;

      const pattern = patterns[patternIdx]!;
      if (this.matchesEvent(event, pattern)) {
        patternIdx++;
      } else if (this.isOutOfOrder(event, patterns, patternIdx)) {
        return { matched: false, received: relevant, failedAt: patternIdx, terminated: true };
      }
    }

    if (patternIdx >= patterns.length) {
      return { matched: true, received: relevant, terminated: true };
    }

    // Not yet complete, but not a failure — caller should await more events
    return { matched: false, received: relevant, terminated: false };
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
