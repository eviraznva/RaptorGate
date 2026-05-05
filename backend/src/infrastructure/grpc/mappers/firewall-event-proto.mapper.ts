import {
  DecryptedIpsMatchEvent,
  EchAttemptDetectedEvent,
  Event,
  IpsSignatureMatchedEvent,
  MlThreatDetectedEvent,
  PinningAutoBypassActivatedEvent,
  PinningFailureDetectedEvent,
  TlsHandshakeFailedEvent,
  TlsUntrustedCertDetectedEvent,
} from '../generated/events/firewall_events.js';
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
  const ipsSignatureMatched = getRuntimeOneofPayload<IpsSignatureMatchedEvent>(
    event.kind,
    'ipsSignatureMatched',
  );
  if (ipsSignatureMatched) {
    return mapIpsSignatureMatched(event, ipsSignatureMatched);
  }

  const decryptedIpsMatch = getRuntimeOneofPayload<DecryptedIpsMatchEvent>(
    event.kind,
    'decryptedIpsMatch',
  );
  if (decryptedIpsMatch) {
    return mapDecryptedIpsMatch(event, decryptedIpsMatch);
  }

  const tlsUntrustedCertDetected =
    getRuntimeOneofPayload<TlsUntrustedCertDetectedEvent>(
      event.kind,
      'tlsUntrustedCertDetected',
    );
  if (tlsUntrustedCertDetected) {
    return mapTlsUntrustedCertDetected(event, tlsUntrustedCertDetected);
  }

  const pinningFailureDetected =
    getRuntimeOneofPayload<PinningFailureDetectedEvent>(
      event.kind,
      'pinningFailureDetected',
    );
  if (pinningFailureDetected) {
    return mapPinningFailureDetected(event, pinningFailureDetected);
  }

  const pinningAutoBypassActivated =
    getRuntimeOneofPayload<PinningAutoBypassActivatedEvent>(
      event.kind,
      'pinningAutoBypassActivated',
    );
  if (pinningAutoBypassActivated) {
    return mapPinningAutoBypassActivated(event, pinningAutoBypassActivated);
  }

  const tlsHandshakeFailed = getRuntimeOneofPayload<TlsHandshakeFailedEvent>(
    event.kind,
    'tlsHandshakeFailed',
  );
  if (tlsHandshakeFailed) {
    return mapTlsHandshakeFailed(event, tlsHandshakeFailed);
  }

  const echAttemptDetected = getRuntimeOneofPayload<EchAttemptDetectedEvent>(
    event.kind,
    'echAttemptDetected',
  );
  if (echAttemptDetected) {
    return mapEchAttemptDetected(event, echAttemptDetected);
  }

  const mlThreatDetected = getRuntimeOneofPayload<MlThreatDetectedEvent>(
    event.kind,
    'mlThreatDetected',
  );
  if (mlThreatDetected) {
    return mapMlThreatDetected(event, mlThreatDetected);
  }

  return null;
}

function getRuntimeOneofPayload<T>(
  kind: Event['kind'],
  caseName: string,
): T | undefined {
  const record = kind as Record<string, unknown> | undefined;
  const item = record?.item;

  if (item && typeof item === 'object' && '$case' in item) {
    const oneof = item as Record<string, unknown>;
    if (oneof.$case === caseName) {
      return oneof[caseName] as T | undefined;
    }
  }

  if (item === caseName) {
    return record?.[caseName] as T | undefined;
  }

  return record?.[caseName] as T | undefined;
}

function mapIpsSignatureMatched(
  event: Event,
  e: IpsSignatureMatchedEvent,
): FirewallEvent {
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

function mapDecryptedIpsMatch(
  event: Event,
  e: DecryptedIpsMatchEvent,
): FirewallEvent {
  return {
    timestamp: toIsoTimestamp(event),
    event_type: 'decrypted_ips_match',
    source: 'TLS',
    decision: e.blocked ? 'block' : 'alert',
    src_ip: undefinedIfEmpty(e.peerIp),
    src_port: e.peerPort,
    dst_ip: undefinedIfEmpty(e.serverIp),
    dst_port: e.serverPort,
    sni: undefinedIfEmpty(e.sni),
    signature_name: undefinedIfEmpty(e.signatureName),
    severity: undefinedIfEmpty(e.severity),
    blocked: e.blocked,
    direction: undefinedIfEmpty(e.direction),
    mode: undefinedIfEmpty(e.mode),
    log_id: undefinedIfEmpty(e.logId),
  };
}

function mapTlsUntrustedCertDetected(
  event: Event,
  e: TlsUntrustedCertDetectedEvent,
): FirewallEvent {
  return {
    timestamp: toIsoTimestamp(event),
    event_type: 'tls_untrusted_cert_detected',
    source: 'TLS',
    decision: 'alert',
    src_ip: undefinedIfEmpty(e.peerIp),
    src_port: e.peerPort,
    dst_ip: undefinedIfEmpty(e.dstIp),
    dst_port: e.dstPort,
    sni: undefinedIfEmpty(e.sni),
    domain: undefinedIfEmpty(e.domain),
    tls_version: undefinedIfEmpty(e.tlsVersion),
  };
}

function mapPinningFailureDetected(
  event: Event,
  e: PinningFailureDetectedEvent,
): FirewallEvent {
  return {
    timestamp: toIsoTimestamp(event),
    event_type: 'pinning_failure_detected',
    source: 'TLS',
    decision: 'alert',
    src_ip: undefinedIfEmpty(e.peerIp),
    src_port: e.peerPort,
    dst_ip: undefinedIfEmpty(e.dstIp),
    dst_port: e.dstPort,
    sni: undefinedIfEmpty(e.sni),
    tls_version: undefinedIfEmpty(e.tlsVersion),
  };
}

function mapPinningAutoBypassActivated(
  event: Event,
  e: PinningAutoBypassActivatedEvent,
): FirewallEvent {
  return {
    timestamp: toIsoTimestamp(event),
    event_type: 'pinning_auto_bypass_activated',
    source: 'TLS',
    decision: 'bypass',
    src_ip: undefinedIfEmpty(e.sourceIp),
    domain: undefinedIfEmpty(e.domain),
    reason: undefinedIfEmpty(e.reason),
  };
}

function mapTlsHandshakeFailed(
  event: Event,
  e: TlsHandshakeFailedEvent,
): FirewallEvent {
  return {
    timestamp: toIsoTimestamp(event),
    event_type: 'tls_handshake_failed',
    source: 'TLS',
    decision: 'error',
    src_ip: undefinedIfEmpty(e.peerIp),
    src_port: e.peerPort,
    dst_ip: undefinedIfEmpty(e.dstIp),
    dst_port: e.dstPort,
    sni: undefinedIfEmpty(e.sni),
    tls_version: undefinedIfEmpty(e.tlsVersion),
    stage: undefinedIfEmpty(e.stage),
    reason: undefinedIfEmpty(e.reason),
    mode: undefinedIfEmpty(e.mode),
  };
}

function mapEchAttemptDetected(
  event: Event,
  e: EchAttemptDetectedEvent,
): FirewallEvent {
  return {
    timestamp: toIsoTimestamp(event),
    event_type: 'ech_attempt_detected',
    source: 'DNS',
    decision: 'alert',
    src_ip: undefinedIfEmpty(e.sourceIp),
    domain: undefinedIfEmpty(e.domain),
    ech_origin: undefinedIfEmpty(e.origin),
    ech_action: undefinedIfEmpty(e.action),
  };
}

function mapMlThreatDetected(
  event: Event,
  e: MlThreatDetectedEvent,
): FirewallEvent {
  return {
    timestamp: toIsoTimestamp(event),
    event_type: 'ml_threat_detected',
    source: 'ML',
    decision: 'alert',
    src_ip: undefinedIfEmpty(e.srcIp),
    src_port: e.srcPort,
    dst_ip: undefinedIfEmpty(e.dstIp),
    dst_port: e.dstPort,
    transport_protocol: undefinedIfEmpty(e.transportProtocol),
    app_protocol: undefinedIfEmpty(e.appProtocol),
    interface: undefinedIfEmpty(e.interface),
    payload_length: e.payloadLength,
    ml_score: e.score,
    ml_threshold: e.threshold,
    model_checksum: undefinedIfEmpty(e.modelChecksum),
    attack_type: undefinedIfEmpty(e.attackType),
  };
}
