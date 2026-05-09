export interface DecryptionMirrorConfigDto {
  enabled: boolean;
  targetHost: string;
  targetPort: number;
  includeClientToServer: boolean;
  includeServerToClient: boolean;
  forwardedOnly: boolean;
  maxSessionBytes: number;
}

export interface DecryptionMirrorConfigResponseDto {
  decryptionMirror: DecryptionMirrorConfigDto;
}
