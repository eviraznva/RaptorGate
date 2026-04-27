import { describe, expect, it, jest } from '@jest/globals';
import type { ClientGrpc } from '@nestjs/microservices';
import { of } from 'rxjs';
import { IpsConfig } from 'src/domain/entities/ips-config.entity';
import { IpsSignature } from 'src/domain/entities/ips-signature.entity';
import { IpsAction as IpsActionVo } from 'src/domain/value-objects/ips-action.vo';
import { IpsAppProtocol as IpsAppProtocolVo } from 'src/domain/value-objects/ips-app-protocol.vo';
import { IpsMatchType as IpsMatchTypeVo } from 'src/domain/value-objects/ips-match-type.vo';
import { IpsPatternEncoding as IpsPatternEncodingVo } from 'src/domain/value-objects/ips-pattern-encoding.vo';
import { Port } from 'src/domain/value-objects/port.vo';
import { RegexPattern } from 'src/domain/value-objects/regex-pattern.vo';
import { SignatureCategory } from 'src/domain/value-objects/signature-category.vo';
import { SignatureSeverity } from 'src/domain/value-objects/signature-severity.vo';
import { Severity } from '../grpc/generated/common/common.js';
import {
  IpsAction,
  IpsAppProtocol,
  IpsMatchType,
  IpsPatternEncoding,
} from '../grpc/generated/config/config_models.js';
import { GrpcFirewallIpsConfigQueryService } from './grpc-firewall-ips-config-query.service.js';

function makeSignature(): IpsSignature {
  return IpsSignature.create(
    '8d3fae59-d1b7-4812-9f31-caf772a9252c',
    'Literal hex',
    true,
    SignatureCategory.create('other'),
    RegexPattern.create('55 4e 49 4f 4e'),
    IpsMatchTypeVo.create('IPS_MATCH_TYPE_LITERAL'),
    IpsPatternEncodingVo.create('IPS_PATTERN_ENCODING_HEX'),
    false,
    SignatureSeverity.create('SEVERITY_HIGH'),
    IpsActionVo.create('IPS_ACTION_BLOCK'),
    [IpsAppProtocolVo.create('IPS_APP_PROTOCOL_HTTP')],
    [Port.create(80)],
    [Port.create(443)],
    new Date('2026-04-20T15:23:56.626Z'),
    new Date('2026-04-20T15:23:56.626Z'),
  );
}

describe('GrpcFirewallIpsConfigQueryService', () => {
  it('sends runtime IPS fields from the domain model during swap', async () => {
    const swapIpsConfig = jest.fn(() => of({}));
    const service = new GrpcFirewallIpsConfigQueryService({
      getService: () => ({
        swapIpsConfig,
        getIpsConfig: jest.fn(),
      }),
    } as unknown as ClientGrpc);

    service.onModuleInit();

    await service.swapIpsConfig(
      IpsConfig.create(
        { enabled: true },
        { enabled: true, maxPayloadBytes: 8192, maxMatchesPerPacket: 10 },
        [makeSignature()],
      ),
    );

    expect(swapIpsConfig).toHaveBeenCalledWith({
      config: {
        general: { enabled: true },
        detection: {
          enabled: true,
          maxPayloadBytes: 8192,
          maxMatchesPerPacket: 10,
        },
        signatures: [
          expect.objectContaining({
            matchType: IpsMatchType.IPS_MATCH_TYPE_LITERAL,
            patternEncoding: IpsPatternEncoding.IPS_PATTERN_ENCODING_HEX,
            caseInsensitive: false,
          }),
        ],
      },
    });
  });

  it('loads runtime IPS fields from firewall responses', async () => {
    const service = new GrpcFirewallIpsConfigQueryService({
      getService: () => ({
        swapIpsConfig: jest.fn(),
        getIpsConfig: () =>
          of({
            config: {
              general: { enabled: true },
              detection: {
                enabled: true,
                maxPayloadBytes: 8192,
                maxMatchesPerPacket: 10,
              },
              signatures: [
                {
                  id: '8d3fae59-d1b7-4812-9f31-caf772a9252c',
                  name: 'Literal hex',
                  enabled: true,
                  category: 'other',
                  pattern: '55 4e 49 4f 4e',
                  severity: Severity.SEVERITY_HIGH,
                  action: IpsAction.IPS_ACTION_BLOCK,
                  appProtocols: [IpsAppProtocol.IPS_APP_PROTOCOL_HTTP],
                  srcPorts: [80],
                  dstPorts: [443],
                  matchType: IpsMatchType.IPS_MATCH_TYPE_LITERAL,
                  patternEncoding: IpsPatternEncoding.IPS_PATTERN_ENCODING_HEX,
                  caseInsensitive: false,
                },
              ],
            },
          }),
      }),
    } as unknown as ClientGrpc);

    service.onModuleInit();

    const config = await service.getIpsConfig();
    const [signature] = config.getSignatures();

    expect(signature.getMatchType().getValue()).toBe('IPS_MATCH_TYPE_LITERAL');
    expect(signature.getPatternEncoding().getValue()).toBe(
      'IPS_PATTERN_ENCODING_HEX',
    );
    expect(signature.getCaseInsensitive()).toBe(false);
  });
});
