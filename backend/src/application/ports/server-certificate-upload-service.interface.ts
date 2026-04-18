export interface UploadServerCertificateInput {
  id: string;
  commonName: string;
  certificatePem: string;
  privateKeyPem: string;
  privateKeyRef: string;
  bindAddress: string;
  bindPort: number;
  inspectionBypass: boolean;
  isActive: boolean;
}

export interface UploadServerCertificateOutput {
  fingerprint: string;
}

export interface IServerCertificateUploadService {
  upload(
    input: UploadServerCertificateInput,
  ): Promise<UploadServerCertificateOutput>;
}

export const SERVER_CERTIFICATE_UPLOAD_SERVICE_TOKEN = Symbol(
  'SERVER_CERTIFICATE_UPLOAD_SERVICE_TOKEN',
);
