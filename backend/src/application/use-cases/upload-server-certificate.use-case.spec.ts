import { readFileSync } from 'node:fs';
import { join } from 'node:path';
import { jest } from '@jest/globals';
import { Test, type TestingModule } from '@nestjs/testing';
import { FirewallCertificate } from '../../domain/entities/firewall-certificate.entity.js';
import {
  FIREWALL_CERTIFICATE_REPOSITORY_TOKEN,
  type IFirewallCertificateRepository,
} from '../../domain/repositories/firewall-certificate.repository.js';
import {
  SERVER_CERTIFICATE_UPLOAD_SERVICE_TOKEN,
  type IServerCertificateUploadService,
} from '../ports/server-certificate-upload-service.interface.js';
import {
  TOKEN_SERVICE_TOKEN,
  type ITokenService,
  type TokenPayload,
} from '../ports/token-service.interface.js';
import { UploadServerCertificateUseCase } from './upload-server-certificate.use-case.js';

describe('UploadServerCertificateUseCase', () => {
  let useCase: UploadServerCertificateUseCase;

  const repository: jest.Mocked<IFirewallCertificateRepository> = {
    save: jest.fn(),
    findById: jest.fn(),
    findAll: jest.fn(),
    findActive: jest.fn(),
    overwriteAll: jest.fn(),
    delete: jest.fn(),
  };

  const tokenService: jest.Mocked<ITokenService> = {
    generateAccessToken: jest.fn(),
    generateRefreshToken: jest.fn(),
    generateTokenPair: jest.fn(),
    verifyAccessToken: jest.fn(),
    decodeAccessToken: jest.fn(),
  };

  const uploadService: jest.Mocked<IServerCertificateUploadService> = {
    upload: jest.fn(),
  };

  const validClaims: TokenPayload = {
    sub: '00000000-0000-4000-8000-000000000001',
    username: 'admin',
  };

  const certificatePem = readFileSync(
    join(process.cwd(), 'devCerts', 'cert.pem'),
    'utf8',
  );
  const privateKeyPem = readFileSync(
    join(process.cwd(), 'devCerts', 'key.pem'),
    'utf8',
  );

  beforeEach(async () => {
    jest.clearAllMocks();

    const module: TestingModule = await Test.createTestingModule({
      providers: [
        UploadServerCertificateUseCase,
        {
          provide: FIREWALL_CERTIFICATE_REPOSITORY_TOKEN,
          useValue: repository,
        },
        {
          provide: TOKEN_SERVICE_TOKEN,
          useValue: tokenService,
        },
        {
          provide: SERVER_CERTIFICATE_UPLOAD_SERVICE_TOKEN,
          useValue: uploadService,
        },
      ],
    }).compile();

    useCase = module.get(UploadServerCertificateUseCase);
  });

  it('creates a new inbound certificate with default flags', async () => {
    tokenService.decodeAccessToken.mockReturnValue(validClaims);
    repository.findAll.mockResolvedValue([]);
    uploadService.upload.mockResolvedValue({ fingerprint: 'FP-NEW' });

    const result = await useCase.execute({
      accessToken: 'valid-token',
      certificatePem,
      privateKeyPem,
      bindAddress: '192.168.20.10',
    });

    expect(uploadService.upload).toHaveBeenCalledTimes(1);
    expect(uploadService.upload).toHaveBeenCalledWith(
      expect.objectContaining({
        bindAddress: '192.168.20.10',
        bindPort: 443,
        inspectionBypass: false,
        isActive: true,
      }),
    );
    expect(repository.save).toHaveBeenCalledTimes(1);

    const saved = repository.save.mock.calls[0][0];
    expect(saved.getBindAddress()).toBe('192.168.20.10');
    expect(saved.getBindPort()).toBe(443);
    expect(saved.getInspectionBypass()).toBe(false);
    expect(saved.getIsActive()).toBe(true);
    expect(saved.getFingerprint()).toBe('FP-NEW');
    expect(result.id).toBe(saved.getId());
    expect(result.bindAddress).toBe('192.168.20.10');
    expect(result.bindPort).toBe(443);
  });

  it('replaces an existing certificate for the same bind address', async () => {
    const existing = FirewallCertificate.create(
      'cert-1',
      'TLS_SERVER',
      'old-name',
      'FP-OLD',
      certificatePem,
      'key-ref-old',
      false,
      new Date('2028-06-16T08:16:15.000Z'),
      new Date('2026-04-01T10:00:00.000Z'),
      '192.168.20.10',
      443,
      true,
    );

    tokenService.decodeAccessToken.mockReturnValue(validClaims);
    repository.findAll.mockResolvedValue([existing]);
    uploadService.upload.mockResolvedValue({ fingerprint: 'FP-ROTATED' });

    const result = await useCase.execute({
      accessToken: 'valid-token',
      certificatePem,
      privateKeyPem,
      bindAddress: '192.168.20.10',
    });

    expect(uploadService.upload).toHaveBeenCalledTimes(1);
    expect(uploadService.upload).toHaveBeenCalledWith(
      expect.objectContaining({
        id: 'cert-1',
        bindAddress: '192.168.20.10',
        bindPort: 443,
        inspectionBypass: true,
        isActive: false,
      }),
    );
    expect(repository.save).toHaveBeenCalledTimes(1);

    const saved = repository.save.mock.calls[0][0];
    expect(saved.getId()).toBe('cert-1');
    expect(saved.getBindAddress()).toBe('192.168.20.10');
    expect(saved.getBindPort()).toBe(443);
    expect(saved.getInspectionBypass()).toBe(true);
    expect(saved.getIsActive()).toBe(false);
    expect(saved.getFingerprint()).toBe('FP-ROTATED');
    expect(saved.getCreatedAt()).toEqual(existing.getCreatedAt());
    expect(result.id).toBe('cert-1');
    expect(result.inspectionBypass).toBe(true);
  });
});
