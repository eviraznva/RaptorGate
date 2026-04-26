import { createHash } from 'node:crypto';
import {
  buildAccessRequest,
  encodeUserPassword,
  extractGroupsFromAttributes,
  parseResponse,
  RADIUS_ATTR_CLASS,
  RADIUS_ATTR_FILTER_ID,
  RADIUS_ATTR_NAS_IP_ADDRESS,
  RADIUS_ATTR_USER_NAME,
  RADIUS_ATTR_USER_PASSWORD,
  RADIUS_ATTR_VENDOR_SPECIFIC,
  RADIUS_CODE_ACCESS_ACCEPT,
  RADIUS_CODE_ACCESS_REJECT,
  RADIUS_CODE_ACCESS_REQUEST,
  verifyResponseAuthenticator,
} from './radius-packet.js';

// Pomocnicza dekoder atrybutow do testow.
function decodeAttributes(buf: Buffer): Map<number, Buffer[]> {
  const out = new Map<number, Buffer[]>();
  let offset = 0;
  while (offset < buf.length) {
    const type = buf.readUInt8(offset);
    const length = buf.readUInt8(offset + 1);
    const value = buf.subarray(offset + 2, offset + length);
    const list = out.get(type) ?? [];
    list.push(value);
    out.set(type, list);
    offset += length;
  }
  return out;
}

function attr(type: number, value: Buffer | string): Buffer {
  const raw = Buffer.isBuffer(value) ? value : Buffer.from(value, 'utf8');
  return Buffer.concat([Buffer.from([type, raw.length + 2]), raw]);
}

describe('radius-packet', () => {
  const secret = 'radiussecret';

  describe('buildAccessRequest', () => {
    it('encoduje Access-Request z User-Name, User-Password i NAS-IP', () => {
      const built = buildAccessRequest({
        username: 'user',
        password: 'user123',
        secret,
        nasIp: '192.168.20.254',
        nasIdentifier: 'raptorgate-backend',
        callingStationId: '192.168.10.10',
      });

      expect(built.packet.readUInt8(0)).toBe(RADIUS_CODE_ACCESS_REQUEST);
      expect(built.packet.readUInt16BE(2)).toBe(built.packet.length);
      expect(built.requestAuthenticator.length).toBe(16);

      const attrs = decodeAttributes(built.packet.subarray(20));
      const userName = attrs.get(RADIUS_ATTR_USER_NAME)?.[0];
      expect(userName?.toString('utf8')).toBe('user');

      const nasIp = attrs.get(RADIUS_ATTR_NAS_IP_ADDRESS)?.[0];
      expect(Array.from(nasIp ?? [])).toEqual([192, 168, 20, 254]);
    });

    it('User-Password dekoduje sie z powrotem do plaintextu', () => {
      const built = buildAccessRequest({
        username: 'user',
        password: 'user123',
        secret,
        nasIp: '192.168.20.254',
        nasIdentifier: 'raptorgate-backend',
        callingStationId: '192.168.10.10',
      });

      const attrs = decodeAttributes(built.packet.subarray(20));
      const cipher = attrs.get(RADIUS_ATTR_USER_PASSWORD)?.[0];
      expect(cipher).toBeDefined();

      // Re-encode the same plaintext z tym samym authenticatorem — musi dac
      // ten sam ciphertext (dowod symetrii encodingu).
      const reencoded = encodeUserPassword(
        'user123',
        Buffer.from(secret, 'utf8'),
        built.requestAuthenticator,
      );
      expect(reencoded.equals(cipher!)).toBe(true);
    });

    it('odrzuca haslo dluzsze niz 128 bajtow (RFC 2865)', () => {
      expect(() =>
        buildAccessRequest({
          username: 'u',
          password: 'a'.repeat(129),
          secret,
          nasIp: '192.168.20.254',
          nasIdentifier: 'r',
          callingStationId: '1.2.3.4',
        }),
      ).toThrow(/exceeds 128/);
    });

    it('odrzuca puste username', () => {
      expect(() =>
        buildAccessRequest({
          username: '',
          password: 'x',
          secret,
          nasIp: '192.168.20.254',
          nasIdentifier: 'r',
          callingStationId: '1.2.3.4',
        }),
      ).toThrow(/empty/);
    });

    it('odrzuca niepoprawny IPv4 dla NAS-IP', () => {
      expect(() =>
        buildAccessRequest({
          username: 'u',
          password: 'p',
          secret,
          nasIp: '999.0.0.1',
          nasIdentifier: 'r',
          callingStationId: '1.2.3.4',
        }),
      ).toThrow(/Invalid IPv4/);
    });
  });

  describe('parseResponse + verifyResponseAuthenticator', () => {
    function buildResponse(
      code: number,
      identifier: number,
      requestAuthenticator: Buffer,
      attributes: Buffer = Buffer.alloc(0),
    ): Buffer {
      const length = 20 + attributes.length;
      const header = Buffer.alloc(4);
      header.writeUInt8(code, 0);
      header.writeUInt8(identifier, 1);
      header.writeUInt16BE(length, 2);

      const respAuth = createHash('md5')
        .update(header)
        .update(requestAuthenticator)
        .update(attributes)
        .update(Buffer.from(secret, 'utf8'))
        .digest();

      return Buffer.concat([header, respAuth, attributes]);
    }

    it('parsuje Access-Accept i akceptuje poprawny authenticator', () => {
      const requestAuth = Buffer.alloc(16, 0xab);
      const buf = buildResponse(RADIUS_CODE_ACCESS_ACCEPT, 42, requestAuth);

      const parsed = parseResponse(buf);
      expect(parsed.code).toBe(RADIUS_CODE_ACCESS_ACCEPT);
      expect(parsed.identifier).toBe(42);
      expect(verifyResponseAuthenticator(parsed, requestAuth, secret)).toBe(
        true,
      );
    });

    it('parsuje Access-Reject', () => {
      const requestAuth = Buffer.alloc(16, 0x11);
      const buf = buildResponse(RADIUS_CODE_ACCESS_REJECT, 7, requestAuth);

      const parsed = parseResponse(buf);
      expect(parsed.code).toBe(RADIUS_CODE_ACCESS_REJECT);
      expect(verifyResponseAuthenticator(parsed, requestAuth, secret)).toBe(
        true,
      );
    });

    it('odrzuca odpowiedz z bledny authenticatorem', () => {
      const requestAuth = Buffer.alloc(16, 0x22);
      const buf = buildResponse(RADIUS_CODE_ACCESS_ACCEPT, 5, requestAuth);
      // Zepsuj ostatni bajt authenticatora.
      buf[19] ^= 0xff;

      const parsed = parseResponse(buf);
      expect(verifyResponseAuthenticator(parsed, requestAuth, secret)).toBe(
        false,
      );
    });

    it('odrzuca pakiet krotszy niz 20 bajtow', () => {
      expect(() => parseResponse(Buffer.alloc(10))).toThrow(/too short/);
    });

    it('odrzuca pakiet z bledynm polem length', () => {
      const buf = Buffer.alloc(20);
      buf.writeUInt8(2, 0);
      buf.writeUInt8(1, 1);
      buf.writeUInt16BE(9999, 2);
      expect(() => parseResponse(buf)).toThrow(/length field invalid/);
    });
  });

  describe('extractGroupsFromAttributes', () => {
    it('wyciaga grupy z Filter-Id, Class i Cisco-AVPair', () => {
      const cisco = Buffer.concat([
        Buffer.from([0, 0, 0, 9]),
        attr(1, 'shell:roles="admins guests"'),
      ]);
      const attrs = Buffer.concat([
        attr(RADIUS_ATTR_FILTER_ID, 'users'),
        attr(RADIUS_ATTR_CLASS, 'guests'),
        attr(RADIUS_ATTR_VENDOR_SPECIFIC, cisco),
      ]);

      expect(extractGroupsFromAttributes(attrs)).toEqual([
        'users',
        'guests',
        'admins',
      ]);
    });
  });
});
