export type AlertSeverity = "info" | "warning" | "critical";

export interface RealtimeAlertDto {
	id: string;
	severity: AlertSeverity;
	message: string;
	source: "firewall" | "system" | "gateway";
	createdAt: string;
}
