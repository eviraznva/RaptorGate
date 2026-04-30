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

  it('maps decryptedIpsMatch to TLS alert or block event', () => {
    const event: Event = {
      kind: {
        item: {
          $case: 'decryptedIpsMatch',
          decryptedIpsMatch: {
            peerIp: '10.0.0.10',
            peerPort: 52123,
            serverIp: '93.184.216.34',
            serverPort: 443,
            sni: 'example.com',
            signatureName: 'Suspicious HTTP header sequence',
            severity: 'high',
            blocked: true,
            direction: 'ClientToServer',
            mode: 'Outbound',
            logId: '01970e9a-4d89-7000-8000-8d4a4df730f2',
          },
        },
      },
    };

    expect(mapFirewallEventFromProto(event)).toMatchObject({
      event_type: 'decrypted_ips_match',
      source: 'TLS',
      decision: 'block',
      src_ip: '10.0.0.10',
      dst_ip: '93.184.216.34',
      sni: 'example.com',
      signature_name: 'Suspicious HTTP header sequence',
      severity: 'high',
      blocked: true,
      direction: 'ClientToServer',
      mode: 'Outbound',
      log_id: '01970e9a-4d89-7000-8000-8d4a4df730f2',
    });
  });

  it('maps tlsUntrustedCertDetected to TLS alert', () => {
    const event: Event = {
      kind: {
        item: {
          $case: 'tlsUntrustedCertDetected',
          tlsUntrustedCertDetected: {
            peerIp: '10.0.0.10',
            peerPort: 52123,
            dstIp: '93.184.216.34',
            dstPort: 443,
            sni: 'example.com',
            domain: 'example.com',
            tlsVersion: 'TLS1.3',
          },
        },
      },
    };

    expect(mapFirewallEventFromProto(event)).toMatchObject({
      event_type: 'tls_untrusted_cert_detected',
      source: 'TLS',
      decision: 'alert',
      src_ip: '10.0.0.10',
      src_port: 52123,
      dst_ip: '93.184.216.34',
      dst_port: 443,
      sni: 'example.com',
      domain: 'example.com',
      tls_version: 'TLS1.3',
    });
  });

  it('maps pinningFailureDetected to TLS alert', () => {
    const event: Event = {
      kind: {
        item: {
          $case: 'pinningFailureDetected',
          pinningFailureDetected: {
            peerIp: '10.0.0.10',
            peerPort: 52123,
            dstIp: '93.184.216.34',
            dstPort: 443,
            sni: 'api.example.com',
            tlsVersion: 'TLS1.3',
          },
        },
      },
    };

    expect(mapFirewallEventFromProto(event)).toMatchObject({
      event_type: 'pinning_failure_detected',
      source: 'TLS',
      decision: 'alert',
      src_ip: '10.0.0.10',
      dst_ip: '93.184.216.34',
      sni: 'api.example.com',
      tls_version: 'TLS1.3',
    });
  });

  it('maps pinningAutoBypassActivated to TLS bypass event', () => {
    const event: Event = {
      kind: {
        item: {
          $case: 'pinningAutoBypassActivated',
          pinningAutoBypassActivated: {
            sourceIp: '10.0.0.10',
            domain: 'api.example.com',
            reason: 'handshake_failure',
          },
        },
      },
    };

    expect(mapFirewallEventFromProto(event)).toMatchObject({
      event_type: 'pinning_auto_bypass_activated',
      source: 'TLS',
      decision: 'bypass',
      src_ip: '10.0.0.10',
      domain: 'api.example.com',
      reason: 'handshake_failure',
    });
  });

  it('maps tlsHandshakeFailed to TLS error', () => {
    const event: Event = {
      kind: {
        item: {
          $case: 'tlsHandshakeFailed',
          tlsHandshakeFailed: {
            peerIp: '10.0.0.10',
            peerPort: 52123,
            dstIp: '93.184.216.34',
            dstPort: 443,
            sni: '',
            tlsVersion: 'TLS1.3',
            stage: 'client_finished',
            reason: 'invalid certificate',
            mode: 'Outbound',
          },
        },
      },
    };

    expect(mapFirewallEventFromProto(event)).toMatchObject({
      event_type: 'tls_handshake_failed',
      source: 'TLS',
      decision: 'error',
      src_ip: '10.0.0.10',
      dst_ip: '93.184.216.34',
      sni: undefined,
      tls_version: 'TLS1.3',
      stage: 'client_finished',
      reason: 'invalid certificate',
      mode: 'Outbound',
    });
  });

  it('maps echAttemptDetected to DNS alert', () => {
    const event: Event = {
      kind: {
        item: {
          $case: 'echAttemptDetected',
          echAttemptDetected: {
            sourceIp: '',
            domain: 'example.com',
            origin: 'dns_https_rr',
            action: 'stripped',
          },
        },
      },
    };

    expect(mapFirewallEventFromProto(event)).toMatchObject({
      event_type: 'ech_attempt_detected',
      source: 'DNS',
      decision: 'alert',
      src_ip: undefined,
      domain: 'example.com',
      ech_origin: 'dns_https_rr',
      ech_action: 'stripped',
    });
  });

  it('maps mlThreatDetected to ML alert', () => {
    const event = {
      kind: {
        item: 'mlThreatDetected',
        mlThreatDetected: {
          score: 0.94,
          threshold: 0.8,
          modelChecksum: 'sha256:abc',
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
    } as unknown as Event;

    expect(mapFirewallEventFromProto(event)).toMatchObject({
      event_type: 'ml_threat_detected',
      source: 'ML',
      decision: 'alert',
      src_ip: '10.0.0.10',
      dst_ip: '93.184.216.34',
      transport_protocol: 'tcp',
      app_protocol: 'tls',
      interface: 'eth0',
      payload_length: 512,
      ml_score: 0.94,
      ml_threshold: 0.8,
      model_checksum: 'sha256:abc',
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
