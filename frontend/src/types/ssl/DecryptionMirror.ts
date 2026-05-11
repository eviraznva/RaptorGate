export interface DecryptionMirrorConfig {
  enabled: boolean;
  targetHost: string;
  targetPort: number;
  includeClientToServer: boolean;
  includeServerToClient: boolean;
  forwardedOnly: boolean;
  maxSessionBytes: number;
}

export type DecryptionMirrorPayload = {
  decryptionMirror: DecryptionMirrorConfig;
};

export const defaultDecryptionMirrorConfig: DecryptionMirrorConfig = {
  enabled: false,
  targetHost: "",
  targetPort: 0,
  includeClientToServer: true,
  includeServerToClient: true,
  forwardedOnly: true,
  maxSessionBytes: 16 * 1024 * 1024,
};
