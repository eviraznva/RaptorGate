import { validate } from 'class-validator';
import { CreateZonePairDto } from './create-zone-pair.dto.js';

const DEFAULT_ZONE_ID = '00000000-0000-0000-0000-000000000000';

describe('CreateZonePairDto', () => {
  it('allows the default zone id as destination zone id', async () => {
    const dto = Object.assign(new CreateZonePairDto(), {
      srcZoneId: '22222222-2222-4222-8222-222222222222',
      dstZoneId: DEFAULT_ZONE_ID,
      defaultPolicy: 'DROP',
    });

    const errors = await validate(dto);

    expect(errors.map((error) => error.property)).not.toContain('dstZoneId');
  });
});
