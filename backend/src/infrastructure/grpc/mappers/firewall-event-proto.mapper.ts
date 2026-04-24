import { Event, IpsSignatureMatchedEvent } from '../generated/events/firewall_events.js';
import {
  FirewallEvent,
  FirewallEventDecision,
} from '../../../domain/firewall-events/firewall-event.js';

function toIsoTimestamp(event: Event): string {
  if (!event.emittedAt) {
    return new Date().toISOString();
  }

  const seconds = Number(event.emittedAt.seconds ?? 0);
  const nanos = Number(event.emittedAt.nanos ?? 0);
  const millis = seconds * 1000 + Math.floor(nanos / 1_000_000);

  return new Date(millis).toISOString();
}

function undefinedIfEmpty(
  value: string | undefined | null,
): string | undefined {
  if (value === undefined || value === null || value === '') {
    return undefined;
  }

  return value;
}

function mapIpsActionToDecision(action: string): FirewallEventDecision {
  const normalized = action.toLowerCase();

  if (
    normalized === 'block' ||
    normalized === 'blocked' ||
    normalized === 'drop' ||
    normalized === 'dropped' ||
    normalized === 'deny' ||
    normalized === 'rejected'
  ) {
    return 'block';
  }

  return 'alert';
}

export function mapFirewallEventFromProto(event: Event): FirewallEvent | null {
  const runtimePayload = getRuntimeOneofPayload(event.kind);
  if (runtimePayload) {
    return mapIpsSignatureMatched(event, runtimePayload);
  }

  const item = event.kind?.item;
  const runtimeItem = item as unknown;

  if (!item) {
    return null;
  }

  if (runtimeItem === 'ipsSignatureMatched') {
    return mapIpsSignatureMatched(event, getRuntimeOneofPayload(event.kind));
  }

  switch (item.$case) {
    case 'ipsSignatureMatched': {
      return mapIpsSignatureMatched(event, item.ipsSignatureMatched);
    }

    default:
      return null;
  }
}

function getRuntimeOneofPayload(
  kind: Event['kind'],
): IpsSignatureMatchedEvent | undefined {
  const record = kind as Record<string, unknown> | undefined;
  return record?.ipsSignatureMatched as IpsSignatureMatchedEvent | undefined;
}

function mapIpsSignatureMatched(
  event: Event,
  e: IpsSignatureMatchedEvent | undefined,
): FirewallEvent | null {
  if (!e) {
    return null;
  }

  return {
    timestamp: toIsoTimestamp(event),
    event_type: 'ips_signature_matched',
    source: 'IPS',
    decision: mapIpsActionToDecision(e.action),
    signature_id: undefinedIfEmpty(e.signatureId),
    signature_name: undefinedIfEmpty(e.signatureName),
    category: undefinedIfEmpty(e.category),
    severity: undefinedIfEmpty(e.severity),
    action: undefinedIfEmpty(e.action),
    src_ip: undefinedIfEmpty(e.srcIp),
    src_port: e.srcPort,
    dst_ip: undefinedIfEmpty(e.dstIp),
    dst_port: e.dstPort,
    transport_protocol: undefinedIfEmpty(e.transportProtocol),
    app_protocol: undefinedIfEmpty(e.appProtocol),
    interface: undefinedIfEmpty(e.interface),
    payload_length: e.payloadLength,
  };
}
