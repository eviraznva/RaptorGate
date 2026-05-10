import { describe, expect, it } from '@jest/globals';
import { NatProtocol } from '../../infrastructure/grpc/generated/common/common.js';
import { NatConfigIsInvalidException } from '../exceptions/nat-config-is-invalid.exception.js';
import { Priority } from '../value-objects/priority.vo.js';
import { NatRule } from './nat-rule.entity.js';

const baseProps = {
  id: '5d375e76-b212-4c9e-8da0-601e5ebb3cd3',
  isActive: true,
  priority: Priority.create(10),
  protocol: NatProtocol.NAT_PROTOCOL_ALL,
  createdAt: new Date('2026-03-20T23:11:43.970Z'),
  updatedAt: new Date('2026-03-20T23:11:43.970Z'),
};

describe('NatRule', () => {
  it('rejects missing action', () => {
    expect(() =>
      NatRule.createWithAction(baseProps, undefined as never),
    ).toThrow(NatConfigIsInvalidException);
  });

  it('rejects unknown action case', () => {
    expect(() =>
      NatRule.createWithAction(baseProps, { $case: 'unknown' } as never),
    ).toThrow(NatConfigIsInvalidException);
  });

  it('rejects action without matching payload', () => {
    expect(() =>
      NatRule.createWithAction(baseProps, { $case: 'snat' } as never),
    ).toThrow(NatConfigIsInvalidException);
  });
});
