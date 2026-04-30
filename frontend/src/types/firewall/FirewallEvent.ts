export type FirewallEvent = {
  timestamp: string;
  event_type: string;
  source: "IPS" | "TLS" | "DNS" | "TCP";
  decision: "decrypt" | "bypass" | "block" | "alert" | "error" | "observe";
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
};
