import { describe, expect, it } from '@jest/globals';
import { IpsSignature } from 'src/domain/entities/ips-signature.entity';
import { IpsAction } from 'src/domain/value-objects/ips-action.vo';
import { IpsAppProtocol } from 'src/domain/value-objects/ips-app-protocol.vo';
import { IpsMatchType } from 'src/domain/value-objects/ips-match-type.vo';
import { IpsPatternEncoding } from 'src/domain/value-objects/ips-pattern-encoding.vo';
import { Port } from 'src/domain/value-objects/port.vo';
import { RegexPattern } from 'src/domain/value-objects/regex-pattern.vo';
import { SignatureCategory } from 'src/domain/value-objects/signature-category.vo';
import { SignatureSeverity } from 'src/domain/value-objects/signature-severity.vo';
import { IpsSignatureJsonMapper } from './ips-signature-json.mapper.js';
import { IpsSignatureRecordSchema } from '../schemas/ips-signatures.schema.js';

describe('IpsSignatureJsonMapper', () => {
  it('defaults missing runtime IPS fields from old JSON records', () => {
    const record = IpsSignatureRecordSchema.parse({
      id: '8d3fae59-d1b7-4812-9f31-caf772a9252c',
      name: 'SQL Injection Attempt',
      isActive: true,
      category: 'sqli',
      pattern: 'UNION\\s+SELECT',
      severity: 'SEVERITY_HIGH',
      action: 'IPS_ACTION_BLOCK',
      appProtocols: ['IPS_APP_PROTOCOL_HTTP'],
      srcPorts: [80],
      dstPorts: [443],
      createdAt: '2026-04-20T15:23:56.626Z',
      updatedAt: '2026-04-20T15:23:56.626Z',
    });

    expect(record.matchType).toBe('IPS_MATCH_TYPE_REGEX');
    expect(record.patternEncoding).toBe('IPS_PATTERN_ENCODING_TEXT');
    expect(record.caseInsensitive).toBe(false);
  });

  it('preserves runtime IPS fields through domain and JSON mapping', () => {
    const signature = IpsSignature.create(
      '8d3fae59-d1b7-4812-9f31-caf772a9252c',
      'Literal hex',
      true,
      SignatureCategory.create('other'),
      RegexPattern.create('55 4e 49 4f 4e'),
      IpsMatchType.create('IPS_MATCH_TYPE_LITERAL'),
      IpsPatternEncoding.create('IPS_PATTERN_ENCODING_HEX'),
      false,
      SignatureSeverity.create('SEVERITY_HIGH'),
      IpsAction.create('IPS_ACTION_BLOCK'),
      [IpsAppProtocol.create('IPS_APP_PROTOCOL_HTTP')],
      [Port.create(80)],
      [Port.create(443)],
      new Date('2026-04-20T15:23:56.626Z'),
      new Date('2026-04-20T15:23:56.626Z'),
    );

    const record = IpsSignatureJsonMapper.toRecord(signature);
    const roundtrip = IpsSignatureJsonMapper.toDomain(record);

    expect(roundtrip.getMatchType().getValue()).toBe('IPS_MATCH_TYPE_LITERAL');
    expect(roundtrip.getPatternEncoding().getValue()).toBe(
      'IPS_PATTERN_ENCODING_HEX',
    );
    expect(roundtrip.getCaseInsensitive()).toBe(false);
  });
});
