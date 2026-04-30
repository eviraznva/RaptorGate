import { describe, expect, it } from '@jest/globals';
import { Event } from '../generated/events/firewall_events.js';
import { mapFirewallEventFromProto } from './firewall-event-proto.mapper.js';

describe('mapFirewallEventFromProto', () => {
  it('maps blocked ipsSignatureMatched to IPS firewall event', () => {
    const event: Event = {
      emittedAt: { seconds: 1_700_000_000, nanos: 0 },
      kind: {
        item: {
          $case: 'ipsSignatureMatched',
          ipsSignatureMatched: {
            signatureId: 'ET-001',
            signatureName: 'ET MALWARE Test',
            category: 'malware',
            severity: 'high',
            action: 'blocked',
            srcIp: '10.0.0.10',
            srcPort: 52123,
            dstIp: '93.184.216.34',
            dstPort: 443,
            transportProtocol: 'tcp',
            appProtocol: 'tls',
            interface: 'eth0',
            payloadLength: 512,
          },
        },
      },
    };

    expect(mapFirewallEventFromProto(event)).toEqual({
      timestamp: new Date(1_700_000_000_000).toISOString(),
      event_type: 'ips_signature_matched',
      source: 'IPS',
      decision: 'block',
      signature_id: 'ET-001',
      signature_name: 'ET MALWARE Test',
      category: 'malware',
      severity: 'high',
      action: 'blocked',
      src_ip: '10.0.0.10',
      src_port: 52123,
      dst_ip: '93.184.216.34',
      dst_port: 443,
      transport_protocol: 'tcp',
      app_protocol: 'tls',
      interface: 'eth0',
      payload_length: 512,
    });
  });

  it('maps non-blocking ipsSignatureMatched to alert decision', () => {
    const event: Event = {
      kind: {
        item: {
          $case: 'ipsSignatureMatched',
          ipsSignatureMatched: {
            signatureId: 'ET-002',
            signatureName: 'ET POLICY Test',
            category: 'policy',
            severity: 'medium',
            action: 'logged',
            srcIp: '10.0.0.10',
            srcPort: 52123,
            dstIp: '93.184.216.34',
            dstPort: 443,
            transportProtocol: 'tcp',
            appProtocol: 'tls',
            interface: 'eth0',
            payloadLength: 512,
          },
        },
      },
    };

    expect(mapFirewallEventFromProto(event)?.decision).toBe('alert');
  });

  it('maps proto-loader oneof shape used at runtime', () => {
    const event = {
      emittedAt: { seconds: 1_700_000_000, nanos: 0 },
      kind: {
        item: 'ipsSignatureMatched',
        ipsSignatureMatched: {
          signatureId: 'ET-003',
          signatureName: 'Runtime Test',
          category: 'other',
          severity: 'critical',
          action: 'block',
          srcIp: '192.168.20.10',
          srcPort: 43590,
          dstIp: '8.8.8.8',
          dstPort: 53,
          transportProtocol: 'udp',
          appProtocol: 'dns',
          interface: 'eth2',
          payloadLength: 39,
        },
      },
    } as unknown as Event;

    expect(mapFirewallEventFromProto(event)).toMatchObject({
      event_type: 'ips_signature_matched',
      source: 'IPS',
      decision: 'block',
      signature_id: 'ET-003',
      src_ip: '192.168.20.10',
      dst_ip: '8.8.8.8',
      transport_protocol: 'udp',
      app_protocol: 'dns',
    });
  });

  it('maps proto-loader shape without oneofs option', () => {
    const event = {
      emittedAt: { seconds: 1_700_000_000, nanos: 0 },
      kind: {
        ipsSignatureMatched: {
          signatureId: 'ET-004',
          signatureName: 'Runtime Test Without Item',
          category: 'other',
          severity: 'critical',
          action: 'block',
          srcIp: '192.168.20.10',
          srcPort: 43590,
          dstIp: '8.8.8.8',
          dstPort: 53,
          transportProtocol: 'udp',
          appProtocol: 'dns',
          interface: 'eth2',
          payloadLength: 39,
        },
      },
    } as unknown as Event;

    expect(mapFirewallEventFromProto(event)).toMatchObject({
      event_type: 'ips_signature_matched',
      source: 'IPS',
      decision: 'block',
      signature_id: 'ET-004',
      src_ip: '192.168.20.10',
      dst_ip: '8.8.8.8',
    });
  });

  it('returns null for unsupported event type', () => {
    const event: Event = {
      kind: {
        item: {
          $case: 'eventBusConnected',
          eventBusConnected: {},
        },
      },
    };

    expect(mapFirewallEventFromProto(event)).toBeNull();
  });
});
