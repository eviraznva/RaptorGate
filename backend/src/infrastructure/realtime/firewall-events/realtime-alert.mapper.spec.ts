import { describe, expect, it } from '@jest/globals';
import { mapFirewallEventToRealtimeAlert } from './realtime-alert.mapper.js';

describe('mapFirewallEventToRealtimeAlert', () => {
  it('maps TLS alert to realtime alert', () => {
    const alert = mapFirewallEventToRealtimeAlert({
      timestamp: '2026-04-29T10:00:00.000Z',
      event_type: 'tls_untrusted_cert_detected',
      source: 'TLS',
      decision: 'alert',
      domain: 'example.com',
    });

    expect(alert).toEqual({
      id: '2026-04-29T10:00:00.000Z:tls_untrusted_cert_detected:example.com',
      severity: 'warning',
      message: 'example.com',
      source: 'firewall',
      createdAt: '2026-04-29T10:00:00.000Z',
    });
  });

  it('maps blocked event to critical alert', () => {
    const alert = mapFirewallEventToRealtimeAlert({
      timestamp: '2026-04-29T10:00:00.000Z',
      event_type: 'decrypted_ips_match',
      source: 'TLS',
      decision: 'block',
      signature_name: 'Blocked decrypted payload',
      severity: 'medium',
    });

    expect(alert).toMatchObject({
      severity: 'critical',
      message: 'Blocked decrypted payload',
    });
  });

  it('maps error event to critical alert', () => {
    const alert = mapFirewallEventToRealtimeAlert({
      timestamp: '2026-04-29T10:00:00.000Z',
      event_type: 'tls_handshake_failed',
      source: 'TLS',
      decision: 'error',
      reason: 'invalid certificate',
    });

    expect(alert).toMatchObject({
      severity: 'critical',
      message: 'invalid certificate',
    });
  });

  it('maps TLS decryption exclusion activation to alert despite bypass decision', () => {
    const alert = mapFirewallEventToRealtimeAlert({
      timestamp: '2026-04-29T10:00:00.000Z',
      event_type: 'tls_decryption_exclusion_activated',
      source: 'TLS',
      decision: 'bypass',
      domain: 'api.example.com',
      reason: 'handshake_failure',
    });

    expect(alert).toMatchObject({
      severity: 'warning',
      message: 'handshake_failure',
    });
  });

  it('does not map observe event to realtime alert', () => {
    expect(
      mapFirewallEventToRealtimeAlert({
        timestamp: '2026-04-29T10:00:00.000Z',
        event_type: 'tcp_session_established',
        source: 'TCP',
        decision: 'observe',
      }),
    ).toBeNull();
  });
});
