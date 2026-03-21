import { ArgumentMetadata, ValidationPipe } from '@nestjs/common';
import { EditNatRuleDto } from './edit-nat-rule.dto';

describe('EditNatRuleDto', () => {
  const metadata: ArgumentMetadata = {
    type: 'body',
    metatype: EditNatRuleDto,
    data: '',
  };

  it('accepts a full UI NAT record when only priority is being changed', async () => {
    const pipe = new ValidationPipe({
      whitelist: true,
      forbidNonWhitelisted: true,
      transform: true,
    });

    const result = await pipe.transform(
      {
        type: 'SNAT',
        priority: 20,
        srcIp: '192.168.1.10',
        dstIp: null,
        srcPort: null,
        dstPort: null,
        translatedIp: '172.16.0.20',
        translatedPort: null,
        createdAt: '2026-03-20T23:11:43.970Z',
        updatedAt: '2026-03-20T23:11:43.970Z',
        createdBy: '00000000-0000-4000-8000-000000000001',
      },
      metadata,
    );

    expect(result).toBeInstanceOf(EditNatRuleDto);
    expect((result as EditNatRuleDto).srcIp).toBe('192.168.1.10');
    expect((result as EditNatRuleDto).dstIp).toBeNull();
    expect(result.priority).toBe(20);
  });
});
