import { createSocket, type Socket } from 'node:dgram';
import { Inject, Injectable, Logger } from '@nestjs/common';
import type {
  IRadiusAuthenticator,
  RadiusAuthRequest,
  RadiusAuthResult,
  RadiusAuthServerOptions,
} from '../../application/ports/radius-authenticator.interface.js';
import {
  buildAccessRequest,
  extractRadiusAttributes,
  parseResponse,
  RADIUS_CODE_ACCESS_ACCEPT,
  RADIUS_CODE_ACCESS_REJECT,
  verifyResponseAuthenticator,
} from './radius/radius-packet.js';

export interface RadiusSendAttempt {
  server: RadiusAuthServerOptions;
  packet: Buffer;
  identifier: number;
  requestAuthenticator: Buffer;
  timeoutMs: number;
}

export type RadiusPacketSender = (attempt: RadiusSendAttempt) => Promise<RadiusAuthResult>;
export const RADIUS_PACKET_SENDER_TOKEN = Symbol('RADIUS_PACKET_SENDER_TOKEN');

// Klient RADIUS PAP nad UDP. Implementuje retransmisje (RADIUS_RETRIES)
// i timeout per probe (RADIUS_TIMEOUT_MS). Zwraca tagged union zamiast
// rzucac wyjatki — use-case rozrozni 4 stany dla audytu.
@Injectable()
export class UdpRadiusAuthenticator implements IRadiusAuthenticator {
  private readonly logger = new Logger(UdpRadiusAuthenticator.name);

  constructor(
    @Inject(RADIUS_PACKET_SENDER_TOKEN)
    private readonly packetSender: RadiusPacketSender | null = null,
  ) {}

  async authenticate(request: RadiusAuthRequest): Promise<RadiusAuthResult> {
    const profile = request.profile;
    if (profile.authenticationProtocol !== 'pap') {
      return { kind: 'error', message: 'unsupported RADIUS authentication protocol' };
    }

    const servers = [...profile.servers].sort((a, b) => a.priority - b.priority);
    if (servers.length === 0) {
      return { kind: 'error', message: 'RADIUS profile has no endpoints' };
    }

    const totalAttempts = profile.retries + 1;
    const attemptedEndpoints: string[] = [];
    let sawTimeout = false;
    let lastError: string | null = null;

    for (const server of servers) {
      attemptedEndpoints.push(server.name);

      let built;
      try {
        built = buildAccessRequest({
          username: request.username,
          password: request.password,
          secret: server.secret,
          nasIp: profile.nasIp,
          nasIdentifier: profile.nasIdentifier,
          calledStationId: profile.calledStationId,
          callingStationId: request.callingStationId,
        });
      } catch (error) {
        lastError = error instanceof Error ? error.message : 'unknown error';
        continue;
      }

      this.logger.log({
        event: 'auth.radius.access_request',
        message: 'sending RADIUS Access-Request',
        username: request.username,
        callingStationId: request.callingStationId,
        identifier: built.identifier,
        endpoint: server.name,
        host: server.host,
        port: server.port,
      });

      for (let attempt = 1; attempt <= totalAttempts; attempt += 1) {
        const result = await this.sendAttempt({
          server,
          packet: built.packet,
          identifier: built.identifier,
          requestAuthenticator: built.requestAuthenticator,
          timeoutMs: profile.timeoutMs,
        });

        if (result.kind === 'accept' || result.kind === 'reject') {
          this.logger.log({
            event:
              result.kind === 'accept'
                ? 'auth.radius.access_accept'
                : 'auth.radius.access_reject',
            message: `RADIUS ${result.kind === 'accept' ? 'Access-Accept' : 'Access-Reject'}`,
            username: request.username,
            endpoint: server.name,
            attempt,
          });
          return { ...result, attemptedEndpoints };
        }

        if (result.kind === 'timeout') {
          sawTimeout = true;
          this.logger.warn({
            event: 'auth.radius.timeout',
            message: 'RADIUS timeout',
            username: request.username,
            endpoint: server.name,
            attempt,
            timeoutMs: profile.timeoutMs,
          });
          continue;
        }

        lastError = result.message;
        this.logger.error({
          event: 'auth.radius.error',
          message: 'RADIUS error',
          username: request.username,
          endpoint: server.name,
          attempt,
          error: result.message,
        });
        break;
      }
    }

    if (lastError) {
      return { kind: 'error', message: lastError, attemptedEndpoints };
    }
    if (sawTimeout) {
      return { kind: 'timeout', attemptedEndpoints };
    }

    return { kind: 'error', message: 'RADIUS attempts exhausted', attemptedEndpoints };
  }

  private sendAttempt(attempt: RadiusSendAttempt): Promise<RadiusAuthResult> {
    if (this.packetSender) {
      return this.packetSender(attempt);
    }

    return this.sendOnce(
      attempt.server.host,
      attempt.server.port,
      attempt.packet,
      attempt.identifier,
      attempt.requestAuthenticator,
      attempt.server.secret,
      attempt.timeoutMs,
    );
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
            const attributes = extractRadiusAttributes(parsed.attributesRaw);
            settle({
              kind: 'accept',
              groups: attributes.userGroups,
              attributes,
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
