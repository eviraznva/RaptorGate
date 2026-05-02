import { IdentitySession } from './identity-session.entity.js';
import { IpAddress } from '../value-objects/ip-address.vo.js';

describe('IdentitySession', () => {
  it('stores replay identity fields', () => {
    const session = IdentitySession.create(
      'sess-1',
      'alice',
      IpAddress.create('10.0.0.10'),
      new Date('2026-05-02T10:00:00.000Z'),
      new Date('2026-05-02T10:30:00.000Z'),
      ['admins'],
      '192.168.20.254',
      'raptorgate',
      'uid=alice,ou=users,dc=raptorgate,dc=local',
      '00:11:22:33:44:55',
    );

    expect(session.getIdentityUserId()).toBe(
      'uid=alice,ou=users,dc=raptorgate,dc=local',
    );
    expect(session.getMacAddress()).toBe('00:11:22:33:44:55');
  });
});
