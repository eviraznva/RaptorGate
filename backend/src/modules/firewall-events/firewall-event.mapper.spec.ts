import { describe, it, expect } from '@jest/globals';
import { mapEventToDocument } from './firewall-event.mapper.js';
import { Event } from '../../infrastructure/grpc/generated/events/firewall_events.js';

function makeEvent(partial: Partial<Event['kind']>): Event {
  return {
    emittedAt: { seconds: 1_700_000_000, nanos: 0 },
    kind: { item: partial?.item },
  } as Event;
}

describe('mapEventToDocument', () => {
  it('maps TLS intercept started to decrypt decision', () => {
    const doc = mapEventToDocument(
      makeEvent({
        item: {
          $case: 'tlsInterceptStarted',
          tlsInterceptStarted: {
            peerIp: '10.0.0.1',
            peerPort: 54321,
            dstIp: '93.184.216.34',
            dstPort: 443,
            sni: 'example.com',
            tlsVersion: 'TLS1.3',
          },
        },
      }),
    );

    expect(doc).not.toBeNull();
    expect(doc!.decision).toBe('decrypt');
    expect(doc!.event_type).toBe('tls_intercept_started');
    expect(doc!.sni).toBe('example.com');
    expect(doc!.tls_version).toBe('TLS1.3');
    expect(doc!.src_ip).toBe('10.0.0.1');
    expect(doc!.dst_port).toBe(443);
    expect(doc!.source).toBe('TLS');
  });

  it('maps blocked decrypted IPS match to block decision with log_id', () => {
    const doc = mapEventToDocument(
      makeEvent({
        item: {
          $case: 'decryptedIpsMatch',
          decryptedIpsMatch: {
            peerIp: '10.0.0.1',
            peerPort: 33000,
            serverIp: '10.0.0.2',
            serverPort: 443,
            sni: 'bad.example',
            signatureName: 'ET MALWARE Test',
            severity: 'high',
            blocked: true,
            direction: 'ClientToServer',
            mode: 'Outbound',
            logId: '0193-aabb',
          },
        },
      }),
    );

    expect(doc!.decision).toBe('block');
    expect(doc!.blocked).toBe(true);
    expect(doc!.log_id).toBe('0193-aabb');
    expect(doc!.signature_name).toBe('ET MALWARE Test');
  });

  it('maps bypass applied to bypass decision', () => {
    const doc = mapEventToDocument(
      makeEvent({
        item: {
          $case: 'tlsBypassApplied',
          tlsBypassApplied: {
            peerIp: '10.0.0.1',
            peerPort: 40000,
            dstIp: '1.1.1.1',
            dstPort: 443,
            sni: 'bank.example',
            domain: 'bank.example',
            tlsVersion: 'TLS1.2',
          },
        },
      }),
    );

    expect(doc!.decision).toBe('bypass');
    expect(doc!.domain).toBe('bank.example');
  });

  it('maps handshake failed to error decision', () => {
    const doc = mapEventToDocument(
      makeEvent({
        item: {
          $case: 'tlsHandshakeFailed',
          tlsHandshakeFailed: {
            peerIp: '10.0.0.1',
            peerPort: 44000,
            dstIp: '93.184.216.34',
            dstPort: 443,
            sni: 'example.com',
            tlsVersion: 'TLS1.3',
            stage: 'server_handshake',
            reason: 'rustls: unknown_ca',
            mode: 'Outbound',
          },
        },
      }),
    );

    expect(doc!.decision).toBe('error');
    expect(doc!.stage).toBe('server_handshake');
    expect(doc!.reason).toBe('rustls: unknown_ca');
  });

  it('maps ECH attempt detected with DNS source', () => {
    const doc = mapEventToDocument(
      makeEvent({
        item: {
          $case: 'echAttemptDetected',
          echAttemptDetected: {
            sourceIp: '',
            domain: 'cloudflare.com',
            origin: 'dns_https_rr',
            action: 'stripped',
          },
        },
      }),
    );

    expect(doc!.source).toBe('DNS');
    expect(doc!.decision).toBe('alert');
    expect(doc!.ech_origin).toBe('dns_https_rr');
    expect(doc!.ech_action).toBe('stripped');
    expect(doc!.src_ip).toBeUndefined();
  });

  it('returns null for empty kind', () => {
    const doc = mapEventToDocument({ emittedAt: undefined, kind: undefined });
    expect(doc).toBeNull();
  });

  it('derives timestamp from emitted_at in ISO format', () => {
    const doc = mapEventToDocument(
      makeEvent({
        item: {
          $case: 'tlsSessionClosed',
          tlsSessionClosed: {
            peerIp: '10.0.0.1',
            peerPort: 50000,
            dstIp: '10.0.0.2',
            dstPort: 443,
            sni: 'example.com',
            bytesUp: 1_234,
            bytesDown: 5_678,
          },
        },
      }),
    );

    expect(doc!.timestamp).toBe(new Date(1_700_000_000_000).toISOString());
    expect(doc!.bytes_up).toBe(1_234);
    expect(doc!.bytes_down).toBe(5_678);
  });
});
