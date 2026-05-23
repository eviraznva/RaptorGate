import { EventEmitter } from 'node:events';
import type { Socket } from 'node:net';
import type { ConnectionOptions, TLSSocket } from 'node:tls';
import { TcpLdapClient } from './tcp-ldap-client.js';

class FakeSocket extends EventEmitter {
  readonly writes: Buffer[] = [];

  setTimeout(): this {
    return this;
  }

  write(packet: Buffer, callback?: (err?: Error) => void): boolean {
    this.writes.push(packet);
    callback?.();
    if (packet.toString('utf8').includes('1.3.6.1.4.1.1466.20037')) {
      queueMicrotask(() => this.emit('data', encodeExtendedResponse(1)));
    }
    return true;
  }

  destroy(): this {
    this.emit('close');
    return this;
  }
}

describe('TcpLdapClient TLS modes', () => {
  it('uses plain TCP when tlsMode is disabled', async () => {
    const socket = new FakeSocket();
    let tcpCalled = false;
    let tlsCalled = false;
    const client = new TcpLdapClient(
      {
        host: 'ldap.example.test',
        port: 389,
        timeoutMs: 1000,
        tlsMode: 'disabled',
        verifyServerCertificate: false,
      },
      {
        connectTcp: () => {
          tcpCalled = true;
          queueMicrotask(() => socket.emit('connect'));
          return socket as unknown as Socket;
        },
        connectTls: () => {
          tlsCalled = true;
          return new FakeSocket() as unknown as TLSSocket;
        },
      },
    );

    await client.connect();

    expect(tcpCalled).toBe(true);
    expect(tlsCalled).toBe(false);
  });

  it('uses TLS connect for ldaps', async () => {
    const socket = new FakeSocket();
    let tlsOptions: ConnectionOptions | null = null;
    const client = new TcpLdapClient(
      {
        host: 'ldap.example.test',
        port: 636,
        timeoutMs: 1000,
        tlsMode: 'ldaps',
        verifyServerCertificate: true,
        servername: 'ldap.example.test',
      },
      {
        connectTcp: () => {
          throw new Error('tcp should not be used');
        },
        connectTls: (options) => {
          tlsOptions = options;
          queueMicrotask(() => socket.emit('secureConnect'));
          return socket as unknown as TLSSocket;
        },
      },
    );

    await client.connect();

    expect(tlsOptions).toMatchObject({
      host: 'ldap.example.test',
      port: 636,
      rejectUnauthorized: true,
      servername: 'ldap.example.test',
    });
  });

  it('sends StartTLS before wrapping the TCP socket', async () => {
    const tcpSocket = new FakeSocket();
    const tlsSocket = new FakeSocket();
    let tlsOptions: ConnectionOptions | null = null;
    const client = new TcpLdapClient(
      {
        host: 'ldap.example.test',
        port: 389,
        timeoutMs: 1000,
        tlsMode: 'starttls',
        verifyServerCertificate: true,
        servername: 'ldap.example.test',
      },
      {
        connectTcp: () => {
          queueMicrotask(() => tcpSocket.emit('connect'));
          return tcpSocket as unknown as Socket;
        },
        connectTls: (options) => {
          tlsOptions = options;
          queueMicrotask(() => tlsSocket.emit('secureConnect'));
          return tlsSocket as unknown as TLSSocket;
        },
      },
    );

    await client.connect();

    expect(tcpSocket.writes[0].toString('utf8')).toContain('1.3.6.1.4.1.1466.20037');
    expect(tlsOptions).toMatchObject({
      rejectUnauthorized: true,
      servername: 'ldap.example.test',
    });
  });
});

function encodeExtendedResponse(messageId: number): Buffer {
  const body = Buffer.concat([integer(0x0a, 0), octet(''), octet('')]);
  return tlv(0x30, Buffer.concat([integer(0x02, messageId), tlv(0x78, body)]));
}

function tlv(tag: number, value: Buffer): Buffer {
  return Buffer.concat([Buffer.from([tag, value.length]), value]);
}

function integer(tag: number, value: number): Buffer {
  return tlv(tag, Buffer.from([value]));
}

function octet(value: string): Buffer {
  return tlv(0x04, Buffer.from(value, 'utf8'));
}
