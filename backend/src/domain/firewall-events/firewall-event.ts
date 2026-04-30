export type FirewallEventSource = 'IPS' | 'TLS' | 'DNS' | 'TCP';

export type FirewallEventDecision =
  | 'decrypt'
  | 'bypass'
  | 'block'
  | 'alert'
  | 'error'
  | 'observe';

export interface FirewallEvent {
  timestamp: string;
  event_type: string;
  source: FirewallEventSource;
  decision: FirewallEventDecision;
  src_ip?: string;
  src_port?: number;
  dst_ip?: string;
  dst_port?: number;
  transport_protocol?: string;
  app_protocol?: string;
  signature_id?: string;
  signature_name?: string;
  category?: string;
  severity?: string;
  action?: string;
  interface?: string;
  payload_length?: number;
}
