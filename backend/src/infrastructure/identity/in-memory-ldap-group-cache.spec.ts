import { describe, expect, it } from '@jest/globals';
import { InMemoryLdapGroupCache } from './in-memory-ldap-group-cache.js';

function makeCache(ttlSeconds: number): InMemoryLdapGroupCache {
  const config = {
    get: () => ttlSeconds,
  } as unknown as ConstructorParameters<typeof InMemoryLdapGroupCache>[0];
  return new InMemoryLdapGroupCache(config);
}

describe('InMemoryLdapGroupCache', () => {
  it('zwraca null gdy brak wpisu', () => {
    const cache = makeCache(60);
    expect(cache.get('user')).toBeNull();
  });

  it('zwraca skopiowane grupy zeby caller nie mogl ich modyfikowac', () => {
    const cache = makeCache(60);
    cache.set('user', ['admins']);
    const got = cache.get('user');
    got?.push('hijack');
    expect(cache.get('user')).toEqual(['admins']);
  });

  it('honoruje TTL — wpis wygasa', () => {
    const cache = makeCache(0.01); // 10 ms
    cache.set('user', ['users']);
    return new Promise<void>((resolve) =>
      setTimeout(() => {
        expect(cache.get('user')).toBeNull();
        resolve();
      }, 30),
    );
  });

  it('invalidate usuwa wpis natychmiast', () => {
    const cache = makeCache(60);
    cache.set('user', ['users']);
    cache.invalidate('user');
    expect(cache.get('user')).toBeNull();
  });
});
