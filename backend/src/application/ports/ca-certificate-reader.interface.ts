export type CaCertificateData = {
  certPem: string;
  fingerprint: string;
  expiresAt: Date;
};

export interface ICaCertificateReader {
  read(): Promise<CaCertificateData>;
}

export const CA_CERTIFICATE_READER_TOKEN = Symbol(
  'CA_CERTIFICATE_READER_TOKEN',
);
