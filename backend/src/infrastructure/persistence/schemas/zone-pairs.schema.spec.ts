import { ZonePairRecordSchema } from './zone-pairs.schema.js';

const DEFAULT_ZONE_ID = '00000000-0000-0000-0000-000000000000';

describe('ZonePairRecordSchema', () => {
  it('allows the default zone id as destination zone id', () => {
    expect(() =>
      ZonePairRecordSchema.parse({
        id: '11111111-1111-4111-8111-111111111111',
        srcZoneId: '22222222-2222-4222-8222-222222222222',
        dstZoneID: DEFAULT_ZONE_ID,
        defaultPolicy: 'DROP',
        createdAt: '2026-05-10T10:00:00.000Z',
        createdBy: '33333333-3333-4333-8333-333333333333',
      }),
    ).not.toThrow();
  });
});
