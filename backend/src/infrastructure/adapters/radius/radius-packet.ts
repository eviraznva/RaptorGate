import { createHash, randomBytes } from 'node:crypto';

// RFC 2865: RADIUS Access-Request z PAP. Eksportowany osobno od adaptera UDP,
// zeby parser/encoder byly testowalne bez sieci.

export const RADIUS_CODE_ACCESS_REQUEST = 1;
export const RADIUS_CODE_ACCESS_ACCEPT = 2;
export const RADIUS_CODE_ACCESS_REJECT = 3;

export const RADIUS_ATTR_USER_NAME = 1;
export const RADIUS_ATTR_USER_PASSWORD = 2;
export const RADIUS_ATTR_NAS_IP_ADDRESS = 4;
export const RADIUS_ATTR_NAS_PORT = 5;
export const RADIUS_ATTR_CALLED_STATION_ID = 30;
export const RADIUS_ATTR_CALLING_STATION_ID = 31;
export const RADIUS_ATTR_NAS_IDENTIFIER = 32;
export const RADIUS_ATTR_NAS_PORT_TYPE = 61;

const HEADER_SIZE = 20;
const MAX_PASSWORD_LENGTH = 128;
const MAX_USERNAME_LENGTH = 253;
const NAS_PORT_TYPE_VIRTUAL = 5;

export interface RadiusAccessRequestInput {
  username: string;
  password: string;
  secret: string;
  nasIp: string;
  nasIdentifier: string;
  callingStationId: string;
}

export interface BuiltAccessRequest {
  packet: Buffer;
  identifier: number;
  requestAuthenticator: Buffer;
}

// Buduje pakiet Access-Request gotowy do wyslania na UDP/1812.
// Generuje losowy identifier (1B) i request authenticator (16B).
export function buildAccessRequest(
  input: RadiusAccessRequestInput,
): BuiltAccessRequest {
  if (Buffer.byteLength(input.username, 'utf8') === 0) {
    throw new Error('RADIUS username must not be empty');
  }
  if (Buffer.byteLength(input.username, 'utf8') > MAX_USERNAME_LENGTH) {
    throw new Error('RADIUS username exceeds 253 bytes');
  }
  if (Buffer.byteLength(input.password, 'utf8') > MAX_PASSWORD_LENGTH) {
    throw new Error('RADIUS password exceeds 128 bytes (RFC 2865)');
  }

  const identifier = randomBytes(1)[0];
  const requestAuthenticator = randomBytes(16);
  const secretBuf = Buffer.from(input.secret, 'utf8');

  const userNameAttr = encodeAttribute(
    RADIUS_ATTR_USER_NAME,
    Buffer.from(input.username, 'utf8'),
  );
  const userPasswordAttr = encodeAttribute(
    RADIUS_ATTR_USER_PASSWORD,
    encodeUserPassword(input.password, secretBuf, requestAuthenticator),
  );
  const nasIpAttr = encodeAttribute(
    RADIUS_ATTR_NAS_IP_ADDRESS,
    encodeIpv4(input.nasIp),
  );
  const nasPortTypeAttr = encodeAttribute(
    RADIUS_ATTR_NAS_PORT_TYPE,
    encodeUint32(NAS_PORT_TYPE_VIRTUAL),
  );
  const nasIdentifierAttr = encodeAttribute(
    RADIUS_ATTR_NAS_IDENTIFIER,
    Buffer.from(input.nasIdentifier, 'utf8'),
  );
  const calledStationAttr = encodeAttribute(
    RADIUS_ATTR_CALLED_STATION_ID,
    Buffer.from(input.nasIdentifier, 'utf8'),
  );
  const callingStationAttr = encodeAttribute(
    RADIUS_ATTR_CALLING_STATION_ID,
    Buffer.from(input.callingStationId, 'utf8'),
  );

  const attributes = Buffer.concat([
    userNameAttr,
    userPasswordAttr,
    nasIpAttr,
    nasPortTypeAttr,
    nasIdentifierAttr,
    calledStationAttr,
    callingStationAttr,
  ]);

  const length = HEADER_SIZE + attributes.length;
  const packet = Buffer.alloc(length);
  packet.writeUInt8(RADIUS_CODE_ACCESS_REQUEST, 0);
  packet.writeUInt8(identifier, 1);
  packet.writeUInt16BE(length, 2);
  requestAuthenticator.copy(packet, 4);
  attributes.copy(packet, HEADER_SIZE);

  return { packet, identifier, requestAuthenticator };
}

export interface ParsedRadiusResponse {
  code: number;
  identifier: number;
  length: number;
  responseAuthenticator: Buffer;
  attributesRaw: Buffer;
}

// Parsuje naglowek odpowiedzi RADIUS bez weryfikacji autentykatora.
export function parseResponse(buffer: Buffer): ParsedRadiusResponse {
  if (buffer.length < HEADER_SIZE) {
    throw new Error(`RADIUS response too short (${buffer.length} bytes)`);
  }

  const code = buffer.readUInt8(0);
  const identifier = buffer.readUInt8(1);
  const length = buffer.readUInt16BE(2);

  if (length < HEADER_SIZE || length > buffer.length) {
    throw new Error(
      `RADIUS response length field invalid (length=${length}, buffer=${buffer.length})`,
    );
  }

  return {
    code,
    identifier,
    length,
    responseAuthenticator: buffer.subarray(4, HEADER_SIZE),
    attributesRaw: buffer.subarray(HEADER_SIZE, length),
  };
}

// Sprawdza Response Authenticator wedlug RFC 2865 sec. 3:
// MD5(Code + Identifier + Length + RequestAuthenticator + Attributes + Secret).
export function verifyResponseAuthenticator(
  response: ParsedRadiusResponse,
  requestAuthenticator: Buffer,
  secret: string,
): boolean {
  const header = Buffer.alloc(4);
  header.writeUInt8(response.code, 0);
  header.writeUInt8(response.identifier, 1);
  header.writeUInt16BE(response.length, 2);

  const expected = createHash('md5')
    .update(header)
    .update(requestAuthenticator)
    .update(response.attributesRaw)
    .update(Buffer.from(secret, 'utf8'))
    .digest();

  return timingSafeEqualBuffer(expected, response.responseAuthenticator);
}

function timingSafeEqualBuffer(a: Buffer, b: Buffer): boolean {
  if (a.length !== b.length) return false;
  let diff = 0;
  for (let i = 0; i < a.length; i += 1) {
    diff |= a[i] ^ b[i];
  }
  return diff === 0;
}

function encodeAttribute(type: number, value: Buffer): Buffer {
  if (value.length > 253) {
    throw new Error(`RADIUS attribute ${type} exceeds 253 bytes`);
  }
  const attr = Buffer.alloc(2 + value.length);
  attr.writeUInt8(type, 0);
  attr.writeUInt8(2 + value.length, 1);
  value.copy(attr, 2);
  return attr;
}

function encodeUint32(value: number): Buffer {
  const buf = Buffer.alloc(4);
  buf.writeUInt32BE(value >>> 0, 0);
  return buf;
}

function encodeIpv4(ip: string): Buffer {
  const parts = ip.split('.').map((p) => Number.parseInt(p, 10));
  if (parts.length !== 4 || parts.some((n) => Number.isNaN(n) || n < 0 || n > 255)) {
    throw new Error(`Invalid IPv4 for NAS-IP-Address: ${ip}`);
  }
  return Buffer.from(parts);
}

// User-Password (attr 2): RFC 2865 sec. 5.2. Padowanie do wielokrotnosci 16,
// XOR z lancuchem MD5(secret || prev_block).
export function encodeUserPassword(
  password: string,
  secret: Buffer,
  requestAuthenticator: Buffer,
): Buffer {
  const passwordBuf = Buffer.from(password, 'utf8');
  const padded = Buffer.alloc(Math.max(16, Math.ceil(passwordBuf.length / 16) * 16));
  passwordBuf.copy(padded, 0);

  const cipher = Buffer.alloc(padded.length);
  let prev = requestAuthenticator;

  for (let offset = 0; offset < padded.length; offset += 16) {
    const block = createHash('md5').update(secret).update(prev).digest();
    for (let i = 0; i < 16; i += 1) {
      cipher[offset + i] = padded[offset + i] ^ block[i];
    }
    prev = cipher.subarray(offset, offset + 16);
  }

  return cipher;
}
