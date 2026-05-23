// RFC 4511: LDAPv3 nad TCP, BER (DER) encoding. Eksportowany osobno od adaptera
// transportowego, zeby parser/encoder byly testowalne bez sieci. Zakres jest
// minimalny — bind simple auth, search z equalityMatch, unbind. Brak SASL,
// brak wszystkich typow filtra, brak controls i referrals.

const TAG_INTEGER = 0x02;
const TAG_OCTET_STRING = 0x04;
const TAG_NULL = 0x05;
const TAG_ENUMERATED = 0x0a;
const TAG_BOOLEAN = 0x01;
const TAG_SEQUENCE = 0x30;

const TAG_BIND_REQUEST = 0x60;
const TAG_BIND_RESPONSE = 0x61;
const TAG_UNBIND_REQUEST = 0x42;
const TAG_SEARCH_REQUEST = 0x63;
const TAG_SEARCH_RESULT_ENTRY = 0x64;
const TAG_SEARCH_RESULT_DONE = 0x65;
const TAG_EXTENDED_REQUEST = 0x77;
const TAG_EXTENDED_RESPONSE = 0x78;
const TAG_SEARCH_RESULT_REFERENCE = 0x73;

const TAG_BIND_SIMPLE_AUTH = 0x80;
const TAG_EXTENDED_REQUEST_NAME = 0x80;
const TAG_FILTER_EQUALITY_MATCH = 0xa3;
const LDAP_STARTTLS_OID = '1.3.6.1.4.1.1466.20037';

export const LDAP_MESSAGE_TAG = TAG_SEQUENCE;
export const LDAP_BIND_REQUEST_TAG = TAG_BIND_REQUEST;
export const LDAP_BIND_RESPONSE_TAG = TAG_BIND_RESPONSE;
export const LDAP_UNBIND_REQUEST_TAG = TAG_UNBIND_REQUEST;
export const LDAP_SEARCH_REQUEST_TAG = TAG_SEARCH_REQUEST;
export const LDAP_SEARCH_RESULT_ENTRY_TAG = TAG_SEARCH_RESULT_ENTRY;
export const LDAP_SEARCH_RESULT_DONE_TAG = TAG_SEARCH_RESULT_DONE;
export const LDAP_EXTENDED_RESPONSE_TAG = TAG_EXTENDED_RESPONSE;

// Result codes per RFC 4511 sec. 4.1.9.
export const LDAP_RESULT_SUCCESS = 0;
export const LDAP_RESULT_NO_SUCH_OBJECT = 32;
export const LDAP_RESULT_INVALID_CREDENTIALS = 49;
export const LDAP_RESULT_INSUFFICIENT_ACCESS_RIGHTS = 50;

export const LDAP_SCOPE_BASE_OBJECT = 0;
export const LDAP_SCOPE_SINGLE_LEVEL = 1;
export const LDAP_SCOPE_WHOLE_SUBTREE = 2;

export const LDAP_DEREF_NEVER = 0;

export const LDAP_PROTOCOL_VERSION = 3;

export interface BindRequestInput {
  messageId: number;
  bindDn: string;
  password: string;
}

export function encodeBindRequest(input: BindRequestInput): Buffer {
  const protocolOp = Buffer.concat([
    encodeInteger(TAG_INTEGER, LDAP_PROTOCOL_VERSION),
    encodeOctetString(TAG_OCTET_STRING, Buffer.from(input.bindDn, 'utf8')),
    encodeOctetString(
      TAG_BIND_SIMPLE_AUTH,
      Buffer.from(input.password, 'utf8'),
    ),
  ]);

  return wrapLdapMessage(
    input.messageId,
    encodeTLV(TAG_BIND_REQUEST, protocolOp),
  );
}

export interface SearchRequestInput {
  messageId: number;
  baseDn: string;
  scope: number;
  // Filtr ograniczony do equalityMatch (attribute=value) — wystarcza dla
  // (uid=...) i (memberUid=...). Jesli kiedys bedziemy potrzebowac AND/OR,
  // doloze to bez zmiany API.
  filterAttribute: string;
  filterValue: string;
  attributes: string[];
  sizeLimit: number;
  timeLimitSeconds: number;
}

export function encodeSearchRequest(input: SearchRequestInput): Buffer {
  if (input.attributes.length === 0) {
    throw new Error('LDAP search requires at least one attribute name');
  }

  const filter = encodeTLV(
    TAG_FILTER_EQUALITY_MATCH,
    Buffer.concat([
      encodeOctetString(
        TAG_OCTET_STRING,
        Buffer.from(input.filterAttribute, 'utf8'),
      ),
      encodeOctetString(
        TAG_OCTET_STRING,
        Buffer.from(input.filterValue, 'utf8'),
      ),
    ]),
  );

  const attributeList = encodeTLV(
    TAG_SEQUENCE,
    Buffer.concat(
      input.attributes.map((name) =>
        encodeOctetString(TAG_OCTET_STRING, Buffer.from(name, 'utf8')),
      ),
    ),
  );

  const protocolOp = Buffer.concat([
    encodeOctetString(TAG_OCTET_STRING, Buffer.from(input.baseDn, 'utf8')),
    encodeInteger(TAG_ENUMERATED, input.scope),
    encodeInteger(TAG_ENUMERATED, LDAP_DEREF_NEVER),
    encodeInteger(TAG_INTEGER, input.sizeLimit),
    encodeInteger(TAG_INTEGER, input.timeLimitSeconds),
    encodeBool(false),
    filter,
    attributeList,
  ]);

  return wrapLdapMessage(
    input.messageId,
    encodeTLV(TAG_SEARCH_REQUEST, protocolOp),
  );
}

export function encodeUnbindRequest(messageId: number): Buffer {
  // UnbindRequest jest [APPLICATION 2] NULL — primitive, dlugosc 0.
  return wrapLdapMessage(
    messageId,
    Buffer.from([TAG_UNBIND_REQUEST, 0x00]),
  );
}

export function encodeStartTlsRequest(messageId: number): Buffer {
  const protocolOp = encodeTLV(
    TAG_EXTENDED_REQUEST,
    encodeOctetString(
      TAG_EXTENDED_REQUEST_NAME,
      Buffer.from(LDAP_STARTTLS_OID, 'utf8'),
    ),
  );

  return wrapLdapMessage(messageId, protocolOp);
}

export interface LdapResultBody {
  resultCode: number;
  matchedDn: string;
  diagnosticMessage: string;
}

export interface BindResponseMessage {
  kind: 'bind-response';
  messageId: number;
  result: LdapResultBody;
}

export interface SearchResultEntryMessage {
  kind: 'search-result-entry';
  messageId: number;
  dn: string;
  attributes: Map<string, string[]>;
}

export interface SearchResultDoneMessage {
  kind: 'search-result-done';
  messageId: number;
  result: LdapResultBody;
}

export interface SearchResultReferenceMessage {
  kind: 'search-result-reference';
  messageId: number;
}

export interface ExtendedResponseMessage {
  kind: 'extended-response';
  messageId: number;
  result: LdapResultBody;
}

export interface UnknownLdapMessage {
  kind: 'unknown';
  messageId: number;
  tag: number;
}

export type ParsedLdapMessage =
  | BindResponseMessage
  | SearchResultEntryMessage
  | SearchResultDoneMessage
  | SearchResultReferenceMessage
  | ExtendedResponseMessage
  | UnknownLdapMessage;

export interface LdapFrame {
  message: ParsedLdapMessage;
  consumed: number;
}

// Probuje zdjac jedna ramke LDAP z bufora; zwraca null gdy danych jeszcze za malo.
export function tryReadLdapFrame(buffer: Buffer): LdapFrame | null {
  const header = peekTLVHeader(buffer);
  if (!header) return null;
  if (header.tag !== TAG_SEQUENCE) {
    throw new Error(
      `LDAP message must start with SEQUENCE, got 0x${header.tag.toString(16)}`,
    );
  }
  const total = header.headerLength + header.length;
  if (buffer.length < total) return null;

  const message = parseLdapMessage(buffer.subarray(0, total));
  return { message, consumed: total };
}

export function parseLdapMessage(buffer: Buffer): ParsedLdapMessage {
  const envelope = readTLV(buffer, 0);
  if (envelope.tag !== TAG_SEQUENCE) {
    throw new Error('LDAP message must be a SEQUENCE');
  }

  const idTlv = readTLV(buffer, envelope.valueOffset);
  if (idTlv.tag !== TAG_INTEGER) {
    throw new Error('LDAP message id must be INTEGER');
  }
  const messageId = readUnsignedInt(buffer, idTlv);

  const op = readTLV(buffer, idTlv.nextOffset);
  switch (op.tag) {
    case TAG_BIND_RESPONSE:
      return {
        kind: 'bind-response',
        messageId,
        result: parseLdapResult(buffer, op),
      };
    case TAG_SEARCH_RESULT_ENTRY: {
      const entry = parseSearchResultEntry(buffer, op);
      return { kind: 'search-result-entry', messageId, ...entry };
    }
    case TAG_SEARCH_RESULT_DONE:
      return {
        kind: 'search-result-done',
        messageId,
        result: parseLdapResult(buffer, op),
      };
    case TAG_SEARCH_RESULT_REFERENCE:
      return { kind: 'search-result-reference', messageId };
    case TAG_EXTENDED_RESPONSE:
      return {
        kind: 'extended-response',
        messageId,
        result: parseLdapResult(buffer, op),
      };
    default:
      return { kind: 'unknown', messageId, tag: op.tag };
  }
}

interface TLV {
  tag: number;
  length: number;
  valueOffset: number;
  nextOffset: number;
}

function readTLV(buffer: Buffer, offset: number): TLV {
  if (offset >= buffer.length) {
    throw new Error('LDAP TLV header truncated');
  }
  const tag = buffer.readUInt8(offset);
  let cursor = offset + 1;
  if (cursor >= buffer.length) {
    throw new Error('LDAP TLV length missing');
  }
  let length = buffer.readUInt8(cursor);
  cursor += 1;
  if ((length & 0x80) !== 0) {
    const numBytes = length & 0x7f;
    if (numBytes === 0 || numBytes > 4) {
      throw new Error('LDAP indefinite or oversized length not supported');
    }
    if (cursor + numBytes > buffer.length) {
      throw new Error('LDAP long-form length truncated');
    }
    length = 0;
    for (let i = 0; i < numBytes; i += 1) {
      length = length * 256 + buffer.readUInt8(cursor + i);
    }
    cursor += numBytes;
  }
  if (cursor + length > buffer.length) {
    throw new Error('LDAP TLV value truncated');
  }
  return {
    tag,
    length,
    valueOffset: cursor,
    nextOffset: cursor + length,
  };
}

interface PeekedHeader {
  tag: number;
  length: number;
  headerLength: number;
}

function peekTLVHeader(buffer: Buffer): PeekedHeader | null {
  if (buffer.length < 2) return null;
  const tag = buffer.readUInt8(0);
  const first = buffer.readUInt8(1);
  if ((first & 0x80) === 0) {
    return { tag, length: first, headerLength: 2 };
  }
  const numBytes = first & 0x7f;
  if (numBytes === 0 || numBytes > 4) {
    throw new Error('LDAP unsupported length form');
  }
  if (buffer.length < 2 + numBytes) return null;
  let length = 0;
  for (let i = 0; i < numBytes; i += 1) {
    length = length * 256 + buffer.readUInt8(2 + i);
  }
  return { tag, length, headerLength: 2 + numBytes };
}

function parseLdapResult(buffer: Buffer, op: TLV): LdapResultBody {
  const codeTlv = readTLV(buffer, op.valueOffset);
  if (codeTlv.tag !== TAG_ENUMERATED) {
    throw new Error('LDAP result code must be ENUMERATED');
  }
  const resultCode = readUnsignedInt(buffer, codeTlv);

  const matchedDnTlv = readTLV(buffer, codeTlv.nextOffset);
  if (matchedDnTlv.tag !== TAG_OCTET_STRING) {
    throw new Error('LDAP matchedDN must be OCTET STRING');
  }
  const matchedDn = buffer
    .subarray(matchedDnTlv.valueOffset, matchedDnTlv.nextOffset)
    .toString('utf8');

  const diagTlv = readTLV(buffer, matchedDnTlv.nextOffset);
  if (diagTlv.tag !== TAG_OCTET_STRING) {
    throw new Error('LDAP diagnosticMessage must be OCTET STRING');
  }
  const diagnosticMessage = buffer
    .subarray(diagTlv.valueOffset, diagTlv.nextOffset)
    .toString('utf8');

  return { resultCode, matchedDn, diagnosticMessage };
}

interface ParsedSearchEntry {
  dn: string;
  attributes: Map<string, string[]>;
}

function parseSearchResultEntry(buffer: Buffer, op: TLV): ParsedSearchEntry {
  const dnTlv = readTLV(buffer, op.valueOffset);
  if (dnTlv.tag !== TAG_OCTET_STRING) {
    throw new Error('LDAP entry DN must be OCTET STRING');
  }
  const dn = buffer.subarray(dnTlv.valueOffset, dnTlv.nextOffset).toString('utf8');

  const attrsTlv = readTLV(buffer, dnTlv.nextOffset);
  if (attrsTlv.tag !== TAG_SEQUENCE) {
    throw new Error('LDAP entry attributes must be SEQUENCE');
  }

  const attributes = new Map<string, string[]>();
  let cursor = attrsTlv.valueOffset;
  while (cursor < attrsTlv.nextOffset) {
    const partialAttr = readTLV(buffer, cursor);
    if (partialAttr.tag !== TAG_SEQUENCE) {
      throw new Error('LDAP partial attribute must be SEQUENCE');
    }

    const nameTlv = readTLV(buffer, partialAttr.valueOffset);
    if (nameTlv.tag !== TAG_OCTET_STRING) {
      throw new Error('LDAP attribute name must be OCTET STRING');
    }
    const name = buffer
      .subarray(nameTlv.valueOffset, nameTlv.nextOffset)
      .toString('utf8');

    const valuesTlv = readTLV(buffer, nameTlv.nextOffset);
    // RFC 4511: PartialAttribute values is SET OF, ale dla decodingu i tak
    // iterujemy dzieci niezaleznie od tego, czy to SET (0x31) czy SEQUENCE.
    const values: string[] = [];
    let valCursor = valuesTlv.valueOffset;
    while (valCursor < valuesTlv.nextOffset) {
      const val = readTLV(buffer, valCursor);
      values.push(buffer.subarray(val.valueOffset, val.nextOffset).toString('utf8'));
      valCursor = val.nextOffset;
    }
    attributes.set(name, values);
    cursor = partialAttr.nextOffset;
  }

  return { dn, attributes };
}

function readUnsignedInt(buffer: Buffer, tlv: TLV): number {
  if (tlv.length === 0) return 0;
  let value = 0;
  for (let i = 0; i < tlv.length; i += 1) {
    value = value * 256 + buffer.readUInt8(tlv.valueOffset + i);
  }
  return value;
}

function wrapLdapMessage(messageId: number, protocolOp: Buffer): Buffer {
  const body = Buffer.concat([
    encodeInteger(TAG_INTEGER, messageId),
    protocolOp,
  ]);
  return encodeTLV(TAG_SEQUENCE, body);
}

function encodeTLV(tag: number, value: Buffer): Buffer {
  return Buffer.concat([Buffer.from([tag]), encodeLength(value.length), value]);
}

function encodeLength(length: number): Buffer {
  if (length < 0) throw new Error('negative LDAP length');
  if (length < 0x80) return Buffer.from([length]);

  const bytes: number[] = [];
  let v = length;
  while (v > 0) {
    bytes.unshift(v & 0xff);
    v = Math.floor(v / 256);
  }
  if (bytes.length > 4) {
    throw new Error('LDAP length exceeds 4-byte long-form limit');
  }
  return Buffer.from([0x80 | bytes.length, ...bytes]);
}

function encodeInteger(tag: number, value: number): Buffer {
  if (!Number.isInteger(value) || value < 0) {
    throw new Error(`LDAP integer must be non-negative integer, got ${value}`);
  }
  if (value === 0) return encodeTLV(tag, Buffer.from([0x00]));
  const bytes: number[] = [];
  let v = value;
  while (v > 0) {
    bytes.unshift(v & 0xff);
    v = Math.floor(v / 256);
  }
  // ASN.1 INTEGER ma byc minimalny w two's complement; dodaj 0x00 gdy wysoki bit ustawiony
  if ((bytes[0] & 0x80) !== 0) bytes.unshift(0x00);
  return encodeTLV(tag, Buffer.from(bytes));
}

function encodeOctetString(tag: number, value: Buffer): Buffer {
  return encodeTLV(tag, value);
}

function encodeBool(value: boolean): Buffer {
  return encodeTLV(TAG_BOOLEAN, Buffer.from([value ? 0xff : 0x00]));
}
