export type SshMatchAction = 'allow' | 'deny';

export interface SshMatch {
  regex: string;
  onMatch: SshMatchAction;
}

export interface SshReasonMatch {
  codes: number[];
  onMatch: SshMatchAction;
}

export interface SshMatchers {
  clientSoftware: SshMatch[];
  serverSoftware: SshMatch[];
  clientProtoVersion: SshMatch[];
  serverProtoVersion: SshMatch[];
  kex: SshMatch[];
  hostKeyAlg: SshMatch[];
  cipher: SshMatch[];
  mac: SshMatch[];
  compression: SshMatch[];
  hostKeyType: SshMatch[];
  disconnectReason: SshReasonMatch[];
}

export function createEmptySshMatchers(): SshMatchers {
  return {
    clientSoftware: [],
    serverSoftware: [],
    clientProtoVersion: [],
    serverProtoVersion: [],
    kex: [],
    hostKeyAlg: [],
    cipher: [],
    mac: [],
    compression: [],
    hostKeyType: [],
    disconnectReason: [],
  };
}
