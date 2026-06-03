import {
  encodeBindRequest,
  encodeSearchRequest,
  encodeStartTlsRequest,
  encodeUnbindRequest,
  LDAP_BIND_REQUEST_TAG,
  LDAP_BIND_RESPONSE_TAG,
  LDAP_MESSAGE_TAG,
  LDAP_RESULT_INVALID_CREDENTIALS,
  LDAP_RESULT_NO_SUCH_OBJECT,
  LDAP_RESULT_SUCCESS,
  LDAP_SCOPE_WHOLE_SUBTREE,
  LDAP_SEARCH_REQUEST_TAG,
  LDAP_SEARCH_RESULT_DONE_TAG,
  LDAP_SEARCH_RESULT_ENTRY_TAG,
  LDAP_UNBIND_REQUEST_TAG,
  parseLdapMessage,
  tryReadLdapFrame,
} from './ldap-message.js';

// Pomocnicze enkodery TLV pod testy parsera, niezalezne od produkcyjnego kodu.
function tlv(tag: number, value: Buffer): Buffer {
  const len = encodeLength(value.length);
  return Buffer.concat([Buffer.from([tag]), len, value]);
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

function encodeBindResponse(
  messageId: number,
  resultCode: number,
  diagnostic = '',
): Buffer {
  const body = Buffer.concat([
    ber(0x0a, resultCode),
    octet(''),
    octet(diagnostic),
  ]);
  const op = tlv(LDAP_BIND_RESPONSE_TAG, body);
  return tlv(LDAP_MESSAGE_TAG, Buffer.concat([ber(0x02, messageId), op]));
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
        tlv(0x31, Buffer.concat(values.map((v) => octet(v)))),
      ]),
    ),
  );
  const op = tlv(
    LDAP_SEARCH_RESULT_ENTRY_TAG,
    Buffer.concat([octet(dn), tlv(0x30, Buffer.concat(partialAttributes))]),
  );
  return tlv(LDAP_MESSAGE_TAG, Buffer.concat([ber(0x02, messageId), op]));
}

function encodeSearchResultDone(messageId: number, resultCode: number): Buffer {
  const body = Buffer.concat([ber(0x0a, resultCode), octet(''), octet('')]);
  const op = tlv(LDAP_SEARCH_RESULT_DONE_TAG, body);
  return tlv(LDAP_MESSAGE_TAG, Buffer.concat([ber(0x02, messageId), op]));
}

describe('ldap-message', () => {
  describe('encodeBindRequest', () => {
    it('zaczyna sie od SEQUENCE i zawiera BindRequest z prawidlowa dlugoscia', () => {
      const packet = encodeBindRequest({
        messageId: 1,
        bindDn: 'cn=admin,dc=raptorgate,dc=local',
        password: 'admin',
      });

      expect(packet.readUInt8(0)).toBe(LDAP_MESSAGE_TAG);
      const totalLength = packet.readUInt8(1) + 2;
      expect(totalLength).toBe(packet.length);

      // Przeskakujemy SEQUENCE TLV header.
      // SEQUENCE { messageID INTEGER (0x02), BindRequest [0x60] ... }
      const messageIdTag = packet.readUInt8(2);
      expect(messageIdTag).toBe(0x02);

      // Po messageID powinien byc tag BindRequest (0x60).
      const messageIdLen = packet.readUInt8(3);
      const bindRequestTag = packet.readUInt8(4 + messageIdLen);
      expect(bindRequestTag).toBe(LDAP_BIND_REQUEST_TAG);
    });
  });

  describe('encodeSearchRequest', () => {
    it('koduje SearchRequest dla equalityMatch (memberUid=user)', () => {
      const packet = encodeSearchRequest({
        messageId: 2,
        baseDn: 'ou=groups,dc=raptorgate,dc=local',
        scope: LDAP_SCOPE_WHOLE_SUBTREE,
        filterAttribute: 'memberUid',
        filterValue: 'user',
        attributes: ['cn'],
        sizeLimit: 0,
        timeLimitSeconds: 5,
      });

      expect(packet.readUInt8(0)).toBe(LDAP_MESSAGE_TAG);
      // Pakiet musi zawierac filtr 0xA3 (equalityMatch) gdzies w body.
      expect(packet.includes(Buffer.from([0xa3]))).toBe(true);
      // Tag SearchRequest 0x63 musi byc obecny.
      expect(packet.includes(Buffer.from([LDAP_SEARCH_REQUEST_TAG]))).toBe(
        true,
      );
    });

    it('rzuca gdy lista atrybutow jest pusta', () => {
      expect(() =>
        encodeSearchRequest({
          messageId: 1,
          baseDn: 'dc=raptorgate,dc=local',
          scope: LDAP_SCOPE_WHOLE_SUBTREE,
          filterAttribute: 'uid',
          filterValue: 'user',
          attributes: [],
          sizeLimit: 1,
          timeLimitSeconds: 1,
        }),
      ).toThrow(/at least one attribute/);
    });
  });

  describe('encodeUnbindRequest', () => {
    it('produkuje pakiet z UnbindRequest [APPLICATION 2] NULL', () => {
      const packet = encodeUnbindRequest(7);
      expect(packet.readUInt8(0)).toBe(LDAP_MESSAGE_TAG);
      // Ostatnie dwa bajty to UnbindRequest tag + dlugosc 0.
      expect(packet[packet.length - 2]).toBe(LDAP_UNBIND_REQUEST_TAG);
      expect(packet[packet.length - 1]).toBe(0);
    });
  });

  describe('encodeStartTlsRequest', () => {
    it('encodes LDAP StartTLS extended request', () => {
      const packet = encodeStartTlsRequest(7);

      expect(tryReadLdapFrame(packet)?.message.messageId).toBe(7);
      expect(packet.toString('hex')).toContain(Buffer.from('1.3.6.1.4.1.1466.20037').toString('hex'));
    });
  });

  describe('parseLdapMessage', () => {
    it('parsuje BindResponse z resultCode success', () => {
      const buffer = encodeBindResponse(1, LDAP_RESULT_SUCCESS, 'OK');
      const message = parseLdapMessage(buffer);
      if (message.kind !== 'bind-response') throw new Error('expected bind');
      expect(message.messageId).toBe(1);
      expect(message.result.resultCode).toBe(LDAP_RESULT_SUCCESS);
      expect(message.result.diagnosticMessage).toBe('OK');
    });

    it('parsuje BindResponse z invalidCredentials', () => {
      const buffer = encodeBindResponse(
        2,
        LDAP_RESULT_INVALID_CREDENTIALS,
        'bad password',
      );
      const message = parseLdapMessage(buffer);
      if (message.kind !== 'bind-response') throw new Error('expected bind');
      expect(message.result.resultCode).toBe(LDAP_RESULT_INVALID_CREDENTIALS);
    });

    it('parsuje SearchResultEntry i wyciaga atrybuty', () => {
      const buffer = encodeSearchResultEntry(
        3,
        'cn=admins,ou=groups,dc=raptorgate,dc=local',
        [{ name: 'cn', values: ['admins'] }],
      );
      const message = parseLdapMessage(buffer);
      if (message.kind !== 'search-result-entry') {
        throw new Error('expected entry');
      }
      expect(message.dn).toContain('cn=admins');
      expect(message.attributes.get('cn')).toEqual(['admins']);
    });

    it('parsuje SearchResultDone z noSuchObject', () => {
      const buffer = encodeSearchResultDone(4, LDAP_RESULT_NO_SUCH_OBJECT);
      const message = parseLdapMessage(buffer);
      if (message.kind !== 'search-result-done') {
        throw new Error('expected done');
      }
      expect(message.result.resultCode).toBe(LDAP_RESULT_NO_SUCH_OBJECT);
    });
  });

  describe('tryReadLdapFrame', () => {
    it('zwraca null gdy ramka jeszcze niekompletna', () => {
      const buffer = encodeBindResponse(1, LDAP_RESULT_SUCCESS).subarray(0, 3);
      expect(tryReadLdapFrame(buffer)).toBeNull();
    });

    it('zdejmuje pojedyncza ramke i raportuje rozmiar', () => {
      const a = encodeBindResponse(1, LDAP_RESULT_SUCCESS);
      const b = encodeSearchResultDone(2, LDAP_RESULT_SUCCESS);
      const concatenated = Buffer.concat([a, b]);

      const first = tryReadLdapFrame(concatenated);
      expect(first).not.toBeNull();
      expect(first?.consumed).toBe(a.length);

      const remaining = concatenated.subarray(first?.consumed ?? 0);
      const second = tryReadLdapFrame(remaining);
      expect(second?.consumed).toBe(b.length);
    });
  });

  describe('encodeBindRequest + parseLdapMessage round-trip via wire-style buffer', () => {
    it('long-form length koduje sie poprawnie dla duzego DN', () => {
      const longDn = `cn=${'x'.repeat(200)},dc=raptorgate,dc=local`;
      const packet = encodeBindRequest({
        messageId: 1,
        bindDn: longDn,
        password: 'admin',
      });

      // Long-form length: drugi bajt powinien miec ustawiony bit 0x80.
      expect((packet.readUInt8(1) & 0x80) !== 0).toBe(true);
    });
  });
});
