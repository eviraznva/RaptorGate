import { connect, type Socket } from 'node:net';
import {
  encodeBindRequest,
  encodeSearchRequest,
  encodeUnbindRequest,
  LDAP_RESULT_NO_SUCH_OBJECT,
  LDAP_RESULT_SUCCESS,
  LDAP_SCOPE_WHOLE_SUBTREE,
  type LdapResultBody,
  type ParsedLdapMessage,
  tryReadLdapFrame,
} from './ldap-message.js';

// Klient LDAPv3 nad TCP. Trzyma jeden socket na operacje (connect -> bind ->
// search* -> unbind). Bez puli polaczen — Issue 4 lookuje grupy przy loginie
// lub przy refresherze, kazdy lookup zaczyna sie i konczy w jednym wywolaniu.

export interface LdapSearchEntry {
  dn: string;
  attributes: Map<string, string[]>;
}

export interface LdapSearchOutcome {
  result: LdapResultBody;
  entries: LdapSearchEntry[];
}

export interface TcpLdapClientOptions {
  host: string;
  port: number;
  timeoutMs: number;
}

interface PendingWaiter {
  matcher: (msg: ParsedLdapMessage) => boolean;
  resolve: (msg: ParsedLdapMessage) => void;
  reject: (err: Error) => void;
}

export class TcpLdapClient {
  private socket: Socket | null = null;
  private inbound: Buffer = Buffer.alloc(0);
  private nextMessageId = 1;
  private waiters: PendingWaiter[] = [];
  private fatalError: Error | null = null;

  constructor(private readonly options: TcpLdapClientOptions) {}

  async connect(): Promise<void> {
    if (this.socket) return;

    await new Promise<void>((resolve, reject) => {
      const socket = connect(this.options.port, this.options.host);
      const timer = setTimeout(() => {
        socket.destroy(new Error('LDAP connect timeout'));
      }, this.options.timeoutMs);

      socket.once('connect', () => {
        clearTimeout(timer);
        socket.setTimeout(this.options.timeoutMs);
        this.socket = socket;
        socket.on('data', (chunk) => this.onData(chunk));
        socket.on('error', (err) => this.onFatal(err));
        socket.on('close', () => this.onFatal(new Error('LDAP socket closed')));
        socket.on('timeout', () =>
          socket.destroy(new Error('LDAP socket timeout')),
        );
        resolve();
      });

      socket.once('error', (err) => {
        clearTimeout(timer);
        reject(err);
      });
    });
  }

  async bind(bindDn: string, password: string): Promise<LdapResultBody> {
    const messageId = this.takeMessageId();
    const packet = encodeBindRequest({ messageId, bindDn, password });
    const response = await this.sendAndAwait(packet, (msg) => {
      if (msg.kind !== 'bind-response') return false;
      return msg.messageId === messageId;
    });

    if (response.kind !== 'bind-response') {
      throw new Error('expected bind-response');
    }
    return response.result;
  }

  async searchEqualityMatch(input: {
    baseDn: string;
    filterAttribute: string;
    filterValue: string;
    attributes: string[];
    sizeLimit: number;
    timeLimitSeconds: number;
  }): Promise<LdapSearchOutcome> {
    const messageId = this.takeMessageId();
    const packet = encodeSearchRequest({
      messageId,
      baseDn: input.baseDn,
      scope: LDAP_SCOPE_WHOLE_SUBTREE,
      filterAttribute: input.filterAttribute,
      filterValue: input.filterValue,
      attributes: input.attributes,
      sizeLimit: input.sizeLimit,
      timeLimitSeconds: input.timeLimitSeconds,
    });

    const entries: LdapSearchEntry[] = [];
    const done = await this.sendAndAwait(packet, (msg) => {
      if (msg.messageId !== messageId) return false;
      if (msg.kind === 'search-result-entry') {
        entries.push({ dn: msg.dn, attributes: msg.attributes });
        return false;
      }
      if (msg.kind === 'search-result-reference') {
        // Pomijamy referrals — labowy slapd ich nie wystawia, a chasing tutaj nie ma sensu.
        return false;
      }
      return msg.kind === 'search-result-done';
    });

    if (done.kind !== 'search-result-done') {
      throw new Error('expected search-result-done');
    }
    return { result: done.result, entries };
  }

  async unbindAndClose(): Promise<void> {
    if (this.fatalError) {
      this.destroySocket();
      return;
    }
    if (!this.socket) return;
    try {
      const messageId = this.takeMessageId();
      this.socket.write(encodeUnbindRequest(messageId));
    } catch {
      // socket juz zamkniety
    }
    this.destroySocket();
  }

  static isResultSuccess(result: LdapResultBody): boolean {
    return result.resultCode === LDAP_RESULT_SUCCESS;
  }

  static isNoSuchObject(result: LdapResultBody): boolean {
    return result.resultCode === LDAP_RESULT_NO_SUCH_OBJECT;
  }

  private takeMessageId(): number {
    const id = this.nextMessageId;
    this.nextMessageId += 1;
    return id;
  }

  private sendAndAwait(
    packet: Buffer,
    matcher: (msg: ParsedLdapMessage) => boolean,
  ): Promise<ParsedLdapMessage> {
    if (this.fatalError) return Promise.reject(this.fatalError);
    if (!this.socket) return Promise.reject(new Error('LDAP not connected'));

    return new Promise<ParsedLdapMessage>((resolve, reject) => {
      const waiter: PendingWaiter = { matcher, resolve, reject };
      this.waiters.push(waiter);

      this.socket?.write(packet, (err) => {
        if (err) {
          this.removeWaiter(waiter);
          reject(err);
        }
      });
    });
  }

  private onData(chunk: Buffer): void {
    this.inbound =
      this.inbound.length === 0 ? chunk : Buffer.concat([this.inbound, chunk]);

    while (this.inbound.length > 0) {
      let frame: ReturnType<typeof tryReadLdapFrame>;
      try {
        frame = tryReadLdapFrame(this.inbound);
      } catch (error) {
        this.onFatal(
          error instanceof Error ? error : new Error('LDAP parse error'),
        );
        return;
      }
      if (!frame) return;

      this.inbound = this.inbound.subarray(frame.consumed);
      this.dispatch(frame.message);
    }
  }

  private dispatch(msg: ParsedLdapMessage): void {
    for (let i = 0; i < this.waiters.length; i += 1) {
      const waiter = this.waiters[i];
      let isFinal: boolean;
      try {
        isFinal = waiter.matcher(msg);
      } catch (error) {
        this.waiters.splice(i, 1);
        waiter.reject(
          error instanceof Error ? error : new Error('LDAP matcher error'),
        );
        return;
      }
      if (isFinal) {
        this.waiters.splice(i, 1);
        waiter.resolve(msg);
        return;
      }
    }
  }

  private onFatal(err: Error): void {
    if (this.fatalError) return;
    this.fatalError = err;
    const waiters = this.waiters;
    this.waiters = [];
    for (const waiter of waiters) {
      try {
        waiter.reject(err);
      } catch {
        // waiter rejected juz poza nasza kontrola
      }
    }
    this.destroySocket();
  }

  private destroySocket(): void {
    if (!this.socket) return;
    try {
      this.socket.destroy();
    } catch {
      // socket juz zamkniety
    }
    this.socket = null;
  }

  private removeWaiter(waiter: PendingWaiter): void {
    const idx = this.waiters.indexOf(waiter);
    if (idx >= 0) this.waiters.splice(idx, 1);
  }
}
