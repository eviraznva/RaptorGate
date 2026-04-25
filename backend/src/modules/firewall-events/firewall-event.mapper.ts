import { Event } from '../../infrastructure/grpc/generated/events/firewall_events.js';
import {
  FirewallEventDecision,
  FirewallEventDocument,
} from './firewall-event.document.js';

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

export function mapEventToDocument(event: Event): FirewallEventDocument | null {
  const item = event.kind?.item;
  if (!item) {
    return null;
  }

  const timestamp = toIsoTimestamp(event);
  const base = (
    source: FirewallEventDocument['source'],
    decision: FirewallEventDecision,
    eventType: string,
  ): FirewallEventDocument => ({
    timestamp,
    source,
    decision,
    event_type: eventType,
  });

  switch (item.$case) {
    case 'tcpSessionEstablished': {
      const e = item.tcpSessionEstablished;
      return {
        ...base('TCP', 'observe', 'tcp_session_established'),
        src_ip: e.src?.ip,
        src_port: e.src?.port,
        dst_ip: e.dst?.ip,
        dst_port: e.dst?.port,
      };
    }
    case 'tcpSessionRemoved': {
      const e = item.tcpSessionRemoved;
      return {
        ...base('TCP', 'observe', 'tcp_session_removed'),
        src_ip: e.src?.ip,
        src_port: e.src?.port,
        dst_ip: e.dst?.ip,
        dst_port: e.dst?.port,
      };
    }
    case 'tcpConnectionRejected': {
      const e = item.tcpConnectionRejected;
      return {
        ...base('TCP', 'block', 'tcp_connection_rejected'),
        src_ip: e.src?.ip,
        src_port: e.src?.port,
        dst_ip: e.dst?.ip,
        dst_port: e.dst?.port,
      };
    }
    case 'tcpSessionAborted': {
      const e = item.tcpSessionAborted;
      return {
        ...base('TCP', 'error', 'tcp_session_aborted'),
        src_ip: e.src?.ip,
        src_port: e.src?.port,
        dst_ip: e.dst?.ip,
        dst_port: e.dst?.port,
      };
    }
    case 'tlsInterceptStarted': {
      const e = item.tlsInterceptStarted;
      return {
        ...base('TLS', 'decrypt', 'tls_intercept_started'),
        src_ip: e.peerIp,
        src_port: e.peerPort,
        dst_ip: e.dstIp,
        dst_port: e.dstPort,
        sni: undefinedIfEmpty(e.sni),
        tls_version: undefinedIfEmpty(e.tlsVersion),
      };
    }
    case 'tlsHandshakeComplete': {
      const e = item.tlsHandshakeComplete;
      return {
        ...base('TLS', 'decrypt', 'tls_handshake_complete'),
        src_ip: e.peerIp,
        src_port: e.peerPort,
        dst_ip: e.dstIp,
        dst_port: e.dstPort,
        sni: undefinedIfEmpty(e.sni),
        alpn: undefinedIfEmpty(e.alpn),
        tls_version: undefinedIfEmpty(e.tlsVersion),
      };
    }
    case 'tlsSessionClosed': {
      const e = item.tlsSessionClosed;
      return {
        ...base('TLS', 'observe', 'tls_session_closed'),
        src_ip: e.peerIp,
        src_port: e.peerPort,
        dst_ip: e.dstIp,
        dst_port: e.dstPort,
        sni: undefinedIfEmpty(e.sni),
        bytes_up: Number(e.bytesUp ?? 0),
        bytes_down: Number(e.bytesDown ?? 0),
      };
    }
    case 'inboundTlsInterceptStarted': {
      const e = item.inboundTlsInterceptStarted;
      return {
        ...base('TLS', 'decrypt', 'inbound_tls_intercept_started'),
        src_ip: e.peerIp,
        src_port: e.peerPort,
        dst_ip: e.serverIp,
        dst_port: e.serverPort,
        sni: undefinedIfEmpty(e.sni),
        common_name: undefinedIfEmpty(e.commonName),
        tls_version: undefinedIfEmpty(e.tlsVersion),
      };
    }
    case 'inboundTlsHandshakeComplete': {
      const e = item.inboundTlsHandshakeComplete;
      return {
        ...base('TLS', 'decrypt', 'inbound_tls_handshake_complete'),
        src_ip: e.peerIp,
        src_port: e.peerPort,
        dst_ip: e.serverIp,
        dst_port: e.serverPort,
        sni: undefinedIfEmpty(e.sni),
        alpn: undefinedIfEmpty(e.alpn),
        tls_version: undefinedIfEmpty(e.tlsVersion),
      };
    }
    case 'inboundTlsSessionClosed': {
      const e = item.inboundTlsSessionClosed;
      return {
        ...base('TLS', 'observe', 'inbound_tls_session_closed'),
        src_ip: e.peerIp,
        src_port: e.peerPort,
        dst_ip: e.serverIp,
        dst_port: e.serverPort,
        sni: undefinedIfEmpty(e.sni),
        bytes_up: Number(e.bytesUp ?? 0),
        bytes_down: Number(e.bytesDown ?? 0),
      };
    }
    case 'decryptedTrafficClassified': {
      const e = item.decryptedTrafficClassified;
      return {
        ...base('TLS', 'observe', 'decrypted_traffic_classified'),
        src_ip: e.peerIp,
        src_port: e.peerPort,
        dst_ip: e.serverIp,
        dst_port: e.serverPort,
        sni: undefinedIfEmpty(e.sni),
        app_proto: undefinedIfEmpty(e.appProto),
        http_version: undefinedIfEmpty(e.httpVersion),
        direction: undefinedIfEmpty(e.direction),
        mode: undefinedIfEmpty(e.mode),
      };
    }
    case 'decryptedIpsMatch': {
      const e = item.decryptedIpsMatch;
      return {
        ...base('TLS', e.blocked ? 'block' : 'alert', 'decrypted_ips_match'),
        src_ip: e.peerIp,
        src_port: e.peerPort,
        dst_ip: e.serverIp,
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
    case 'tlsUntrustedCertDetected': {
      const e = item.tlsUntrustedCertDetected;
      return {
        ...base('TLS', 'alert', 'tls_untrusted_cert_detected'),
        src_ip: e.peerIp,
        src_port: e.peerPort,
        dst_ip: e.dstIp,
        dst_port: e.dstPort,
        sni: undefinedIfEmpty(e.sni),
        domain: undefinedIfEmpty(e.domain),
        tls_version: undefinedIfEmpty(e.tlsVersion),
      };
    }
    case 'tlsBypassApplied': {
      const e = item.tlsBypassApplied;
      return {
        ...base('TLS', 'bypass', 'tls_bypass_applied'),
        src_ip: e.peerIp,
        src_port: e.peerPort,
        dst_ip: e.dstIp,
        dst_port: e.dstPort,
        sni: undefinedIfEmpty(e.sni),
        domain: undefinedIfEmpty(e.domain),
        tls_version: undefinedIfEmpty(e.tlsVersion),
      };
    }
    case 'inboundTlsBypassApplied': {
      const e = item.inboundTlsBypassApplied;
      return {
        ...base('TLS', 'bypass', 'inbound_tls_bypass_applied'),
        src_ip: e.peerIp,
        src_port: e.peerPort,
        dst_ip: e.serverIp,
        dst_port: e.serverPort,
        sni: undefinedIfEmpty(e.sni),
        tls_version: undefinedIfEmpty(e.tlsVersion),
      };
    }
    case 'pinningFailureDetected': {
      const e = item.pinningFailureDetected;
      return {
        ...base('TLS', 'alert', 'pinning_failure_detected'),
        src_ip: e.peerIp,
        src_port: e.peerPort,
        dst_ip: e.dstIp,
        dst_port: e.dstPort,
        sni: undefinedIfEmpty(e.sni),
        tls_version: undefinedIfEmpty(e.tlsVersion),
      };
    }
    case 'pinningAutoBypassActivated': {
      const e = item.pinningAutoBypassActivated;
      return {
        ...base('TLS', 'bypass', 'pinning_auto_bypass_activated'),
        src_ip: undefinedIfEmpty(e.sourceIp),
        domain: undefinedIfEmpty(e.domain),
        reason: undefinedIfEmpty(e.reason),
      };
    }
    case 'tlsHandshakeFailed': {
      const e = item.tlsHandshakeFailed;
      return {
        ...base('TLS', 'error', 'tls_handshake_failed'),
        src_ip: e.peerIp,
        src_port: e.peerPort,
        dst_ip: e.dstIp,
        dst_port: e.dstPort,
        sni: undefinedIfEmpty(e.sni),
        tls_version: undefinedIfEmpty(e.tlsVersion),
        stage: undefinedIfEmpty(e.stage),
        reason: undefinedIfEmpty(e.reason),
        mode: undefinedIfEmpty(e.mode),
      };
    }
    case 'echAttemptDetected': {
      const e = item.echAttemptDetected;
      return {
        ...base('DNS', 'alert', 'ech_attempt_detected'),
        src_ip: undefinedIfEmpty(e.sourceIp),
        domain: undefinedIfEmpty(e.domain),
        ech_origin: undefinedIfEmpty(e.origin),
        ech_action: undefinedIfEmpty(e.action),
      };
    }
    case 'mlThreatDetected': {
      const e = item.mlThreatDetected;
      return {
        ...base('ML', 'alert', 'ml_threat_detected'),
        src_ip: e.srcIp,
        src_port: e.srcPort,
        dst_ip: e.dstIp,
        dst_port: e.dstPort,
        app_proto: undefinedIfEmpty(e.appProtocol),
        ml_score: e.score,
        ml_threshold: e.threshold,
        model_checksum: undefinedIfEmpty(e.modelChecksum),
      };
    }
    default:
      return null;
  }
}
