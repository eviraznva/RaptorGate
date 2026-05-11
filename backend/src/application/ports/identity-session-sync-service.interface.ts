// Port warstwy aplikacji: sync aktywnej sesji identity do firewalla.
// ADR 0002: sesje ida osobnym kanalem gRPC (IdentitySessionService),
// poza mechanizmem PushActiveConfigSnapshot.
// TODO(Issue 3): wywolywane po zalogowaniu (upsert) i wylogowaniu / expire (revoke).

export interface IdentitySessionSyncPayload {
  id: string;
  identityUserId: string;
  radiusUsername: string;
  macAddress: string;
  ipAddress: string;
  nasIp: string;
  calledStationId: string;
  authenticatedAt: Date;
  expiresAt: Date;
  groups: string[];
}

export interface IIdentitySessionSyncService {
  upsertIdentitySession(session: IdentitySessionSyncPayload): Promise<void>;

  // Zwraca true, jesli firewall mial aktywna sesje pod tym IP i ja usunal.
  revokeIdentitySession(ipAddress: string): Promise<boolean>;
}

export const IDENTITY_SESSION_SYNC_SERVICE_TOKEN = Symbol(
  'IDENTITY_SESSION_SYNC_SERVICE_TOKEN',
);
