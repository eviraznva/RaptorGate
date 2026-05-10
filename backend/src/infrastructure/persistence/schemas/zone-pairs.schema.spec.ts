import { ZonePairsFileSchema } from './zone-pairs.schema.js';

const defaultZoneId = '00000000-0000-0000-0000-000000000000';
const serversZoneId = '22222222-2222-4222-8222-222222222222';
const createdBy = '00000000-0000-4000-8000-000000000001';

describe('ZonePairsFileSchema', () => {
  it('accepts default zone id as source or destination zone', () => {
    expect(() =>
      ZonePairsFileSchema.parse({
        items: [
          {
            id: '55555555-aaaa-4555-8555-555555555555',
            srcZoneId: serversZoneId,
            dstZoneID: defaultZoneId,
            defaultPolicy: 'ALLOW',
            createdAt: '2026-04-27T00:00:00.000Z',
            createdBy,
          },
          {
            id: '66666666-aaaa-4666-8666-666666666666',
            srcZoneId: defaultZoneId,
            dstZoneID: serversZoneId,
            defaultPolicy: 'ALLOW',
            createdAt: '2026-04-27T00:00:00.000Z',
            createdBy,
          },
        ],
      }),
    ).not.toThrow();
  });
});
