export type IdentitySession = {
  sessionId: string;
  sourceIp: string;
  username: string;
  groups: string[];
  createdAt: string;
  expiresAt: string;
};
