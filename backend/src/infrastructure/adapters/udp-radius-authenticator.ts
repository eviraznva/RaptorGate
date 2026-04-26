import { createSocket, type Socket } from 'node:dgram';
import { Inject, Injectable, Logger } from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import type {
  IRadiusAuthenticator,
  RadiusAuthRequest,
  RadiusAuthResult,
} from '../../application/ports/radius-authenticator.interface.js';
import type { Env } from '../../shared/config/env.validation.js';
import {
  buildAccessRequest,
  extractGroupsFromAttributes,
  parseResponse,
  RADIUS_CODE_ACCESS_ACCEPT,
  RADIUS_CODE_ACCESS_REJECT,
  verifyResponseAuthenticator,
} from './radius/radius-packet.js';

// Klient RADIUS PAP nad UDP. Implementuje retransmisje (RADIUS_RETRIES)
// i timeout per probe (RADIUS_TIMEOUT_MS). Zwraca tagged union zamiast
// rzucac wyjatki — use-case rozrozni 4 stany dla audytu.
@Injectable()
export class UdpRadiusAuthenticator implements IRadiusAuthenticator {
  private readonly logger = new Logger(UdpRadiusAuthenticator.name);

  constructor(
    @Inject(ConfigService)
    private readonly configService: ConfigService<Env, true>,
  ) {}

  async authenticate(request: RadiusAuthRequest): Promise<RadiusAuthResult> {
    const host = this.configService.get('RADIUS_HOST', { infer: true });
    const port = this.configService.get('RADIUS_PORT', { infer: true });
    const secret = this.configService.get('RADIUS_SECRET', { infer: true });
    const timeoutMs = this.configService.get('RADIUS_TIMEOUT_MS', {
      infer: true,
    });
    const retries = this.configService.get('RADIUS_RETRIES', { infer: true });
    const nasIp = this.configService.get('RADIUS_NAS_IP', { infer: true });
    const nasIdentifier = this.configService.get('RADIUS_NAS_IDENTIFIER', {
      infer: true,
    });

    let built;
    try {
      built = buildAccessRequest({
        username: request.username,
        password: request.password,
        secret,
        nasIp,
        nasIdentifier,
        callingStationId: request.callingStationId,
      });
    } catch (error) {
      const message = error instanceof Error ? error.message : 'unknown error';
      return { kind: 'error', message };
    }

    this.logger.log({
      event: 'auth.radius.access_request',
      message: 'sending RADIUS Access-Request',
      username: request.username,
      callingStationId: request.callingStationId,
      identifier: built.identifier,
      host,
      port,
    });

    const totalAttempts = retries + 1;
    let lastError: string | null = null;

    for (let attempt = 1; attempt <= totalAttempts; attempt += 1) {
      const result = await this.sendOnce(
        host,
        port,
        built.packet,
        built.identifier,
        built.requestAuthenticator,
        secret,
        timeoutMs,
      );

      if (result.kind === 'accept' || result.kind === 'reject') {
        this.logger.log({
          event:
            result.kind === 'accept'
              ? 'auth.radius.access_accept'
              : 'auth.radius.access_reject',
          message: `RADIUS ${result.kind === 'accept' ? 'Access-Accept' : 'Access-Reject'}`,
          username: request.username,
          attempt,
        });
        return result;
      }

      if (result.kind === 'timeout') {
        this.logger.warn({
          event: 'auth.radius.timeout',
          message: 'RADIUS timeout',
          username: request.username,
          attempt,
          timeoutMs,
        });
        if (attempt === totalAttempts) {
          return { kind: 'timeout' };
        }
        continue;
      }

      lastError = result.message;
      this.logger.error({
        event: 'auth.radius.error',
        message: 'RADIUS error',
        username: request.username,
        attempt,
        error: result.message,
      });
      if (attempt === totalAttempts) {
        return { kind: 'error', message: result.message };
      }
    }

    return { kind: 'error', message: lastError ?? 'RADIUS attempts exhausted' };
  }

  private sendOnce(
    host: string,
    port: number,
    packet: Buffer,
    expectedIdentifier: number,
    requestAuthenticator: Buffer,
    secret: string,
    timeoutMs: number,
  ): Promise<RadiusAuthResult> {
    return new Promise((resolve) => {
      const socket: Socket = createSocket('udp4');
      let settled = false;

      const settle = (result: RadiusAuthResult) => {
        if (settled) return;
        settled = true;
        clearTimeout(timer);
        try {
          socket.close();
        } catch {
          // socket juz zamkniety
        }
        resolve(result);
      };

      const timer = setTimeout(() => settle({ kind: 'timeout' }), timeoutMs);

      socket.on('error', (err) => {
        settle({ kind: 'error', message: err.message });
      });

      socket.on('message', (msg) => {
        try {
          const parsed = parseResponse(msg);

          if (parsed.identifier !== expectedIdentifier) {
            // Pakiet z innej tury — ignorujemy i czekamy dalej.
            return;
          }
          if (
            !verifyResponseAuthenticator(parsed, requestAuthenticator, secret)
          ) {
            settle({
              kind: 'error',
              message: 'invalid RADIUS Response Authenticator',
            });
            return;
          }

          if (parsed.code === RADIUS_CODE_ACCESS_ACCEPT) {
            settle({
              kind: 'accept',
              groups: extractGroupsFromAttributes(parsed.attributesRaw),
            });
          } else if (parsed.code === RADIUS_CODE_ACCESS_REJECT) {
            settle({ kind: 'reject', reason: 'Access-Reject' });
          } else {
            settle({
              kind: 'error',
              message: `unexpected RADIUS code ${parsed.code}`,
            });
          }
        } catch (error) {
          const message =
            error instanceof Error ? error.message : 'parse error';
          settle({ kind: 'error', message });
        }
      });

      socket.send(packet, 0, packet.length, port, host, (err) => {
        if (err) {
          settle({ kind: 'error', message: err.message });
        }
      });
    });
  }
}
