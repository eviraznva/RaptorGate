export type RealtimeAlertDto = {
  id: string;
  severity: 'info' | 'warning' | 'critical';
  message: string;
  source: string;
  createdAt: string;
};
