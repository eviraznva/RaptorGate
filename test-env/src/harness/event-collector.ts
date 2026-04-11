import { match, P } from 'ts-pattern';

export interface EventMatcher {
  kind: Record<string, unknown>;
  match?: Record<string, unknown>;
}

export interface Event {
  emitted_at?: { seconds: number | string; nanos: number };
  kind?: {
    item?: string;
    [key: string]: unknown;
  };
  [key: string]: unknown;
}

export interface WaitForResult {
  matched: boolean;
  received: Event[];
  failedAt?: number;
}

const VM_CLOCK_OFFSET_MS = parseInt(process.env.VM_CLOCK_OFFSET_MS ?? '0', 10);

export class EventCollector {
  private buffer: Event[] = [];
  private fenceMs = 0;

  setFence(): void {
    this.fenceMs = Date.now() + VM_CLOCK_OFFSET_MS;
  }

  push(event: Event): void {
    this.buffer.push(event);
  }

  async waitForSubsequence(
    patterns: EventMatcher[],
    timeout: number,
  ): Promise<WaitForResult> {
    if (patterns.length === 0) {
      return { matched: true, received: [] };
    }

    const start = Date.now();
    let patternIdx = 0;

    while (Date.now() - start < timeout) {
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

    return { matched: false, received: this.buffer, failedAt: patternIdx };
  }

  private isAfterFence(event: Event): boolean {
    if (!event.emitted_at) return false;
    const seconds =
      typeof event.emitted_at.seconds === 'string'
        ? parseInt(event.emitted_at.seconds, 10)
        : event.emitted_at.seconds;
    const eventMs = seconds * 1000 + (event.emitted_at.nanos ?? 0) / 1_000_000;
    return eventMs > this.fenceMs;
  }

  private matchesEvent(event: Event, pattern: EventMatcher): boolean {
    const kindItem = event.kind?.item;
    const expectedKind = pattern.kind?.item;

    if (expectedKind && kindItem !== expectedKind) {
      return false;
    }

    if (!pattern.match) {
      return true;
    }

    const payload = this.extractPayload(event, expectedKind as string | undefined);
    if (!payload) return false;

    try {
      return match(payload)
        .with(pattern.match as any, () => true)
        .otherwise(() => false);
    } catch {
      return this.shallowMatch(payload, pattern.match);
    }
  }

  private extractPayload(event: Event, kind?: string): Record<string, unknown> | null {
    if (!kind || !event.kind) return null;
    const snakeKind = (kind as string).replace(/([A-Z])/g, '_$1').toLowerCase();
    return (event.kind as any)[snakeKind] ?? null;
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
    event: Event,
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
