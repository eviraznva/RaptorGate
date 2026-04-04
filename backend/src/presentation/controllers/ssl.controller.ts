import {
  Controller,
  Get,
  HttpCode,
  HttpStatus,
  Inject,
  Query,
  Res,
  BadRequestException,
} from '@nestjs/common';
import {
  ApiError401,
  ApiError403,
  ApiError404,
  ApiError429,
  ApiError500,
} from '../decorators/api-error-response.decorator.js';
import { ApiOkEnvelope } from '../decorators/api-envelope-response.decorator.js';
import { GetCaCertificateUseCase } from '../../application/use-cases/get-ca-certificate.use-case.js';
import { RequirePermissions } from '../decorators/auth/require-permissions.decorator.js';
import { GetCaCertificateResponseDto } from '../dtos/get-ca-certificate-response.dto.js';
import { ResponseMessage } from '../decorators/response-message.decorator.js';
import { Roles } from '../decorators/auth/roles.decorator.js';
import { Permission } from '../../domain/enums/permissions.enum.js';
import { ApiOperation, ApiQuery } from '@nestjs/swagger';
import { Role } from '../../domain/enums/role.enum.js';
import type { Response } from 'express';

@Controller('ssl')
export class SslController {
  constructor(
    @Inject(GetCaCertificateUseCase)
    private readonly getCaCertificateUseCase: GetCaCertificateUseCase,
  ) {}

  @ApiOperation({
    summary: 'Get CA certificate metadata',
    description:
      'Returns the CA certificate PEM, SHA-256 fingerprint and expiration date.',
  })
  @Roles(Role.Viewer)
  @RequirePermissions(Permission.CERTIFICATES_READ)
  @Get('ca')
  @HttpCode(HttpStatus.OK)
  @ResponseMessage('CA certificate retrieved')
  @ApiOkEnvelope(GetCaCertificateResponseDto, 'CA certificate retrieved')
  @ApiError401('Access token is missing, invalid, or expired')
  @ApiError403('Insufficient permissions to read CA certificate')
  @ApiError404('CA certificate not found')
  @ApiError429('Too many requests')
  @ApiError500('Internal server error while retrieving CA certificate')
  async getCaCertificate(): Promise<GetCaCertificateResponseDto> {
    const data = await this.getCaCertificateUseCase.execute();
    return {
      certPem: data.certPem,
      fingerprint: data.fingerprint,
      expiresAt: data.expiresAt,
    };
  }

  @ApiOperation({
    summary: 'Download CA certificate file',
    description:
      'Downloads the CA certificate as a file in PEM or DER format for installation on client devices.',
  })
  @ApiQuery({
    name: 'format',
    enum: ['pem', 'der'],
    required: false,
    description: 'Certificate format (default: pem)',
  })
  @Roles(Role.Viewer)
  @RequirePermissions(Permission.CERTIFICATES_READ)
  @Get('ca/download')
  @HttpCode(HttpStatus.OK)
  @ApiError401('Access token is missing, invalid, or expired')
  @ApiError403('Insufficient permissions to download CA certificate')
  @ApiError404('CA certificate not found')
  @ApiError429('Too many requests')
  @ApiError500('Internal server error while downloading CA certificate')
  async downloadCaCertificate(
    @Query('format') format: string = 'pem',
    @Res() res: Response,
  ): Promise<void> {
    const data = await this.getCaCertificateUseCase.execute();

    if (format === 'pem') {
      res
        .set({
          'Content-Type': 'application/x-pem-file',
          'Content-Disposition': 'attachment; filename="raptorgate-ca.crt"',
        })
        .send(data.certPem);
      return;
    }

    if (format === 'der') {
      const pemBody = data.certPem
        .replace(/-----BEGIN CERTIFICATE-----/, '')
        .replace(/-----END CERTIFICATE-----/, '')
        .replace(/\s/g, '');
      const derBuffer = Buffer.from(pemBody, 'base64');

      res
        .set({
          'Content-Type': 'application/x-x509-ca-cert',
          'Content-Disposition': 'attachment; filename="raptorgate-ca.der"',
        })
        .send(derBuffer);
      return;
    }

    throw new BadRequestException(
      'Invalid format — supported values: pem, der',
    );
  }
}
