import { Injectable } from '@nestjs/common';

@Injectable()
export class Mutex {
  private queue: Promise<void> = Promise.resolve();

  async runExclusive<T>(fn: () => Promise<T>): Promise<T> {
    let release!: () => void;

    const lock = new Promise<void>((resolve) => (release = resolve));

    const prev = this.queue;
    this.queue = prev.then(() => lock);

    await prev;
    try {
      return await fn();
    } finally {
      release();
    }
  }
}
