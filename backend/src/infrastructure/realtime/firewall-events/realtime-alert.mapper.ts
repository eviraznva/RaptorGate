import type { RealtimeAlertDto } from '../../../application/dtos/realtime-alert.dto.js';
import type { FirewallEvent } from '../../../domain/firewall-events/firewall-event.js';

export function mapFirewallEventToRealtimeAlert(
  event: FirewallEvent,
): RealtimeAlertDto | null {
  if (!shouldPublishAlert(event)) {
    return null;
  }

  return {
    id: buildAlertId(event),
    severity: mapAlertSeverity(event),
    message: buildAlertMessage(event),
    source: 'firewall',
    createdAt: event.timestamp,
  };
}

function shouldPublishAlert(event: FirewallEvent): boolean {
  return (
    event.decision === 'alert' ||
    event.decision === 'block' ||
    event.decision === 'error' ||
    event.event_type === 'tls_decryption_exclusion_activated'
  );
}

function buildAlertId(event: FirewallEvent): string {
  return [
    event.timestamp,
    event.event_type,
    event.signature_id ?? event.src_ip ?? event.domain ?? event.sni ?? '',
  ].join(':');
}

function mapAlertSeverity(event: FirewallEvent): RealtimeAlertDto['severity'] {
  if (event.decision === 'block' || event.decision === 'error') {
    return 'critical';
  }

  const severity = event.severity?.toLowerCase();
  if (severity === 'critical' || severity === 'high') {
    return 'critical';
  }

  return 'warning';
}

function buildAlertMessage(event: FirewallEvent): string {
  return (
    event.signature_name ??
    event.reason ??
    event.domain ??
    event.sni ??
    `${event.event_type} ${event.src_ip ?? ''} -> ${event.dst_ip ?? ''}`.trim()
  );
}
