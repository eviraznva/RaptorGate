import { Injectable, Logger, OnModuleInit } from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import { Env } from '../../shared/config/env.validation.js';
import { FirewallEventDocument } from './firewall-event.document.js';

const FLUSH_INTERVAL_MS = 1_000;
const MAX_BATCH_SIZE = 256;
const INDEX_TEMPLATE_NAME = 'raptorgate-fw-events';

const INDEX_TEMPLATE = {
  index_patterns: ['raptorgate-fw-events-*'],
  template: {
    settings: {
      number_of_shards: 1,
      number_of_replicas: 0,
    },
    mappings: {
      properties: {
        timestamp: { type: 'date' },
        event_type: { type: 'keyword' },
        source: { type: 'keyword' },
        decision: { type: 'keyword' },
        src_ip: { type: 'ip' },
        src_port: { type: 'integer' },
        dst_ip: { type: 'ip' },
        dst_port: { type: 'integer' },
        sni: { type: 'keyword' },
        tls_version: { type: 'keyword' },
        alpn: { type: 'keyword' },
        domain: { type: 'keyword' },
        app_proto: { type: 'keyword' },
        http_version: { type: 'keyword' },
        direction: { type: 'keyword' },
        mode: { type: 'keyword' },
        signature_name: { type: 'keyword' },
        severity: { type: 'keyword' },
        blocked: { type: 'boolean' },
        log_id: { type: 'keyword' },
        stage: { type: 'keyword' },
        reason: { type: 'text' },
        bytes_up: { type: 'long' },
        bytes_down: { type: 'long' },
        common_name: { type: 'keyword' },
        ech_origin: { type: 'keyword' },
        ech_action: { type: 'keyword' },
      },
    },
  },
};

@Injectable()
export class OpenSearchSink implements OnModuleInit {
  private readonly logger = new Logger(OpenSearchSink.name);
  private readonly baseUrl?: string;
  private readonly authHeader?: string;
  private readonly indexPrefix: string;
  private readonly insecureTls: boolean;
  private readonly buffer: FirewallEventDocument[] = [];
  private flushTimer?: NodeJS.Timeout;
  private templateReady = false;

  constructor(configService: ConfigService<Env, true>) {
    const rawUrl = configService.get('OPENSEARCH_URL', { infer: true });
    this.baseUrl = rawUrl ? rawUrl.replace(/\/+$/, '') : undefined;
    const username = configService.get('OPENSEARCH_USERNAME', {
      infer: true,
    });
    const password = configService.get('OPENSEARCH_PASSWORD', {
      infer: true,
    });
    if (username && password) {
      this.authHeader =
        'Basic ' + Buffer.from(`${username}:${password}`).toString('base64');
    }
    this.indexPrefix = configService.get('OPENSEARCH_INDEX_PREFIX', {
      infer: true,
    });
    this.insecureTls = configService.get('OPENSEARCH_INSECURE_TLS', {
      infer: true,
    });
  }

  onModuleInit(): void {
    if (!this.baseUrl) {
      this.logger.warn(
        'OPENSEARCH_URL not set, firewall events will be logged only',
      );
      return;
    }

    if (this.insecureTls) {
      process.env.NODE_TLS_REJECT_UNAUTHORIZED = '0';
      this.logger.warn(
        'OpenSearch insecure TLS enabled (NODE_TLS_REJECT_UNAUTHORIZED=0)',
      );
    }

    this.flushTimer = setInterval(() => {
      void this.flush();
    }, FLUSH_INTERVAL_MS);
    this.flushTimer.unref();

    void this.ensureIndexTemplate();
  }

  ingest(doc: FirewallEventDocument): void {
    if (!this.baseUrl) {
      this.logger.debug(`fw-event: ${JSON.stringify(doc)}`);
      return;
    }
    this.buffer.push(doc);
    if (this.buffer.length >= MAX_BATCH_SIZE) {
      void this.flush();
    }
  }

  private indexNameFor(doc: FirewallEventDocument): string {
    const day = doc.timestamp.slice(0, 10).replace(/-/g, '.');
    return `${this.indexPrefix}-${day}`;
  }

  private async ensureIndexTemplate(): Promise<void> {
    if (!this.baseUrl || this.templateReady) {
      return;
    }
    try {
      const response = await fetch(
        `${this.baseUrl}/_index_template/${INDEX_TEMPLATE_NAME}`,
        {
          method: 'PUT',
          headers: this.buildHeaders('application/json'),
          body: JSON.stringify(INDEX_TEMPLATE),
        },
      );
      if (!response.ok) {
        const body = await response.text();
        this.logger.error(
          `Failed to install index template: ${response.status} ${body}`,
        );
        return;
      }
      this.templateReady = true;
      this.logger.log(
        `OpenSearch index template '${INDEX_TEMPLATE_NAME}' ready`,
      );
    } catch (err) {
      this.logger.error(
        `OpenSearch template install error: ${(err as Error).message}`,
      );
    }
  }

  private async flush(): Promise<void> {
    if (!this.baseUrl || this.buffer.length === 0) {
      return;
    }
    if (!this.templateReady) {
      await this.ensureIndexTemplate();
    }

    const batch = this.buffer.splice(0, this.buffer.length);
    const body =
      batch
        .map((doc) => {
          const indexLine = JSON.stringify({
            index: { _index: this.indexNameFor(doc) },
          });
          return `${indexLine}\n${JSON.stringify(doc)}`;
        })
        .join('\n') + '\n';

    try {
      const response = await fetch(`${this.baseUrl}/_bulk`, {
        method: 'POST',
        headers: this.buildHeaders('application/x-ndjson'),
        body,
      });
      if (!response.ok) {
        const text = await response.text();
        this.logger.error(
          `OpenSearch bulk failed: ${response.status} ${text.slice(0, 500)}`,
        );
      }
    } catch (err) {
      this.logger.error(`OpenSearch bulk error: ${(err as Error).message}`);
    }
  }

  private buildHeaders(contentType: string): Record<string, string> {
    const headers: Record<string, string> = { 'content-type': contentType };
    if (this.authHeader) {
      headers.authorization = this.authHeader;
    }
    return headers;
  }
}
