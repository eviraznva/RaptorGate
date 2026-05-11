export interface PortalSession {
  authenticated: boolean;
  sourceIp: string;
  sessionId?: string;
  username?: string;
  authenticatedAt?: string;
  expiresAt?: string;
  groups?: string[];
}

export interface PortalLoginRequest {
  username: string;
  password: string;
}

export interface PortalLoginSuccess {
  sessionId: string;
  username: string;
  sourceIp: string;
  authenticatedAt: string;
  expiresAt: string;
}

export interface PortalLogoutResult {
  removed: boolean;
}
