import { SecretRecord } from './secret-record.entity.js';

describe('SecretRecord', () => {
  it('creates encrypted managed secret metadata', () => {
    const createdAt = new Date('2026-04-30T10:00:00.000Z');
    const updatedAt = new Date('2026-04-30T10:01:00.000Z');

    const record = SecretRecord.create(
      'secret://identity/radius/default',
      'ciphertext',
      'iv',
      'auth-tag',
      createdAt,
      updatedAt,
      'user-1',
    );

    expect(record.getRef()).toBe('secret://identity/radius/default');
    expect(record.getCiphertext()).toBe('ciphertext');
    expect(record.getIv()).toBe('iv');
    expect(record.getAuthTag()).toBe('auth-tag');
    expect(record.getCreatedAt()).toBe(createdAt);
    expect(record.getUpdatedAt()).toBe(updatedAt);
    expect(record.getUpdatedBy()).toBe('user-1');
  });

  it('rejects environment references in managed storage', () => {
    const now = new Date('2026-04-30T10:00:00.000Z');

    expect(() =>
      SecretRecord.create('env:RADIUS_SECRET', 'ciphertext', 'iv', 'auth-tag', now, now, 'user-1'),
    ).toThrow();
  });
});
