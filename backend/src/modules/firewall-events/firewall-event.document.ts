export type FirewallEventDecision =
  | 'decrypt'
  | 'bypass'
  | 'block'
  | 'alert'
  | 'error'
  | 'observe';

export interface FirewallEventDocument {
  timestamp: string;
  event_type: string;
  source: 'TLS' | 'DNS' | 'TCP';
  decision: FirewallEventDecision;
  src_ip?: string;
  src_port?: number;
  dst_ip?: string;
  dst_port?: number;
  sni?: string;
  tls_version?: string;
  alpn?: string;
  domain?: string;
  app_proto?: string;
  direction?: string;
  mode?: string;
  signature_name?: string;
  severity?: string;
  blocked?: boolean;
  log_id?: string;
  stage?: string;
  reason?: string;
  bytes_up?: number;
  bytes_down?: number;
  common_name?: string;
  ech_origin?: string;
  ech_action?: string;
}
