import { createServer, type Server, type Socket } from 'node:net';
import {
  LDAP_BIND_REQUEST_TAG,
  LDAP_BIND_RESPONSE_TAG,
  LDAP_MESSAGE_TAG,
  LDAP_RESULT_SUCCESS,
  LDAP_SEARCH_REQUEST_TAG,
  LDAP_SEARCH_RESULT_DONE_TAG,
  LDAP_SEARCH_RESULT_ENTRY_TAG,
  LDAP_UNBIND_REQUEST_TAG,
  tryReadLdapFrame,
} from './ldap-message.js';
import { TcpLdapDirectoryAdapter } from './tcp-ldap-directory.js';

function tlv(tag: number, value: Buffer): Buffer {
  return Buffer.concat([Buffer.from([tag]), encodeLength(value.length), value]);
}

function encodeLength(length: number): Buffer {
  if (length < 0x80) return Buffer.from([length]);
  const bytes: number[] = [];
  let v = length;
  while (v > 0) {
    bytes.unshift(v & 0xff);
    v = Math.floor(v / 256);
  }
  return Buffer.from([0x80 | bytes.length, ...bytes]);
}

function ber(tag: number, value: number): Buffer {
  if (value === 0) return tlv(tag, Buffer.from([0x00]));
  const bytes: number[] = [];
  let v = value;
  while (v > 0) {
    bytes.unshift(v & 0xff);
    v = Math.floor(v / 256);
  }
  if ((bytes[0] & 0x80) !== 0) bytes.unshift(0x00);
  return tlv(tag, Buffer.from(bytes));
}

function octet(value: string): Buffer {
  return tlv(0x04, Buffer.from(value, 'utf8'));
}

function encodeBindResponse(messageId: number): Buffer {
  const body = Buffer.concat([ber(0x0a, LDAP_RESULT_SUCCESS), octet(''), octet('')]);
  return tlv(
    LDAP_MESSAGE_TAG,
    Buffer.concat([ber(0x02, messageId), tlv(LDAP_BIND_RESPONSE_TAG, body)]),
  );
}

function encodeSearchResultEntry(
  messageId: number,
  dn: string,
  attributes: Array<{ name: string; values: string[] }>,
): Buffer {
  const partialAttributes = attributes.map(({ name, values }) =>
    tlv(
      0x30,
      Buffer.concat([
        octet(name),
        tlv(0x31, Buffer.concat(values.map((value) => octet(value)))),
      ]),
    ),
  );
  return tlv(
    LDAP_MESSAGE_TAG,
    Buffer.concat([
      ber(0x02, messageId),
      tlv(
        LDAP_SEARCH_RESULT_ENTRY_TAG,
        Buffer.concat([octet(dn), tlv(0x30, Buffer.concat(partialAttributes))]),
      ),
    ]),
  );
}

function encodeSearchResultDone(messageId: number): Buffer {
  const body = Buffer.concat([ber(0x0a, LDAP_RESULT_SUCCESS), octet(''), octet('')]);
  return tlv(
    LDAP_MESSAGE_TAG,
    Buffer.concat([ber(0x02, messageId), tlv(LDAP_SEARCH_RESULT_DONE_TAG, body)]),
  );
}

function makeConfig(port: number): ConstructorParameters<typeof TcpLdapDirectoryAdapter>[0] {
  const values = new Map<string, unknown>([
    ['IDENTITY_LDAP_ENABLED', true],
    ['IDENTITY_LDAP_HOST', '127.0.0.1'],
    ['IDENTITY_LDAP_PORT', port],
    ['IDENTITY_LDAP_BIND_DN', 'cn=admin,dc=raptorgate,dc=local'],
    ['IDENTITY_LDAP_BIND_PASSWORD', 'admin'],
    ['IDENTITY_LDAP_USER_BASE_DN', 'ou=users,dc=raptorgate,dc=local'],
    ['IDENTITY_LDAP_USER_FILTER_ATTRIBUTE', 'uid'],
    ['IDENTITY_LDAP_GROUP_BASE_DN', 'ou=groups,dc=raptorgate,dc=local'],
    ['IDENTITY_LDAP_GROUP_MEMBER_ATTRIBUTE', 'memberUid'],
    ['IDENTITY_LDAP_GROUP_NAME_ATTRIBUTE', 'cn'],
    ['IDENTITY_LDAP_TIMEOUT_MS', 500],
  ]);

  return {
    get: (key: string) => values.get(key),
  } as unknown as ConstructorParameters<typeof TcpLdapDirectoryAdapter>[0];
}

async function startFakeLdap(): Promise<{
  port: number;
  requests: Buffer[];
  close: () => Promise<void>;
}> {
  const requests: Buffer[] = [];
  const sockets = new Set<Socket>();
  const server: Server = createServer((socket) => {
    sockets.add(socket);
    socket.on('close', () => sockets.delete(socket));

    let inbound = Buffer.alloc(0);
    let searchCount = 0;

    socket.on('data', (chunk) => {
      inbound = inbound.length === 0 ? chunk : Buffer.concat([inbound, chunk]);

      while (inbound.length > 0) {
        const frame = tryReadLdapFrame(inbound);
        if (!frame) return;

        requests.push(Buffer.from(inbound.subarray(0, frame.consumed)));
        inbound = inbound.subarray(frame.consumed);

        if (frame.message.kind !== 'unknown') continue;
        if (frame.message.tag === LDAP_BIND_REQUEST_TAG) {
          socket.write(encodeBindResponse(frame.message.messageId));
        } else if (frame.message.tag === LDAP_SEARCH_REQUEST_TAG) {
          searchCount += 1;
          if (searchCount === 1) {
            socket.write(
              encodeSearchResultEntry(
                frame.message.messageId,
                'uid=admin,ou=users,dc=raptorgate,dc=local',
                [],
              ),
            );
          } else {
            socket.write(
              encodeSearchResultEntry(
                frame.message.messageId,
                'cn=admins,ou=groups,dc=raptorgate,dc=local',
                [{ name: 'cn', values: ['admins'] }],
              ),
            );
            socket.write(
              encodeSearchResultEntry(
                frame.message.messageId,
                'cn=auditors,ou=groups,dc=raptorgate,dc=local',
                [{ name: 'cn', values: ['auditors'] }],
              ),
            );
          }
          socket.write(encodeSearchResultDone(frame.message.messageId));
        } else if (frame.message.tag === LDAP_UNBIND_REQUEST_TAG) {
          socket.end();
        }
      }
    });
  });

  await new Promise<void>((resolve) => server.listen(0, '127.0.0.1', resolve));
  const address = server.address();
  if (!address || typeof address === 'string') {
    throw new Error('fake LDAP server did not bind to TCP');
  }

  return {
    port: address.port,
    requests,
    close: async () => {
      for (const socket of sockets) socket.destroy();
      await new Promise<void>((resolve, reject) =>
        server.close((error) => (error ? reject(error) : resolve())),
      );
    },
  };
}

describe('TcpLdapDirectoryAdapter', () => {
  it('binduje i pobiera grupy uzytkownika przez LDAP', async () => {
    const fake = await startFakeLdap();
    try {
      const adapter = new TcpLdapDirectoryAdapter(makeConfig(fake.port));

      const result = await adapter.resolveGroups('admin');

      expect(result).toEqual({
        kind: 'ok',
        userDn: 'uid=admin,ou=users,dc=raptorgate,dc=local',
        groups: ['admins', 'auditors'],
      });
      const requestPayload = Buffer.concat(fake.requests);
      expect(requestPayload.includes(Buffer.from('uid'))).toBe(true);
      expect(requestPayload.includes(Buffer.from('admin'))).toBe(true);
      expect(requestPayload.includes(Buffer.from('memberUid'))).toBe(true);
    } finally {
      await fake.close();
    }
  });
});
