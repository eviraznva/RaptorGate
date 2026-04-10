import path from 'node:path';
import * as grpc from '@grpc/grpc-js';
import * as protoLoader from '@grpc/proto-loader';
import type { Event } from './generated/events/firewall_events';

// test-env/src/server.ts → __dirname = test-env/src
// ../ = test-env/  → ../../ = repo root
const PROTO_ROOT = path.resolve(__dirname, '../../proto');
const PORT = 50052;

const PROTO_FILES = [
  path.join(PROTO_ROOT, 'services', 'event_service.proto'),
  path.join(PROTO_ROOT, 'events', 'firewall_events.proto'),
  path.join(PROTO_ROOT, 'common', 'common.proto'),
];

const LOADER_OPTIONS = {
  keepCase: false,
  longs: String,
  enums: String,
  defaults: true,
  oneofs: true,
  includeDirs: [PROTO_ROOT],
};

function formatEvent(event: Event): string {
  const lines: string[] = [];
  lines.push('─'.repeat(60));
  lines.push('  INCOMING GRPC EVENT');
  lines.push('─'.repeat(60));

  if (event.emittedAt) {
    const ts = event.emittedAt as any;
    const dateStr = typeof ts === 'object' && ts.seconds
      ? new Date(Number(ts.seconds) * 1000).toISOString()
      : String(ts);
    lines.push(`  emitted_at : ${dateStr}`);
  }

  if (event.kind) {
    const kind = event.kind as any;
    // proto-loader represents oneofs as { item: "...", <camelCaseField>: {...} }
    const item = kind.item || Object.keys(kind).find(k => typeof kind[k] === 'object' && k !== 'item');
    const eventKey = typeof item === 'string' ? item : Object.keys(kind).find(k => typeof kind[k] === 'object');
    const payload = eventKey ? kind[eventKey] : null;

    switch (eventKey) {
      case 'tcpSessionEstablished':
        lines.push('  kind       : TcpSessionEstablished');
        lines.push(`  src        : ${payload?.src?.ip ?? '?'}:${payload?.src?.port ?? '?'}`);
        lines.push(`  dst        : ${payload?.dst?.ip ?? '?'}:${payload?.dst?.port ?? '?'}`);
        break;
      case 'tcpSessionRemoved':
        lines.push('  kind       : TcpSessionRemoved');
        lines.push(`  src        : ${payload?.src?.ip ?? '?'}:${payload?.src?.port ?? '?'}`);
        lines.push(`  dst        : ${payload?.dst?.ip ?? '?'}:${payload?.dst?.port ?? '?'}`);
        break;
      case 'tcpConnectionRejected':
        lines.push('  kind       : TcpConnectionRejected');
        lines.push(`  src        : ${payload?.src?.ip ?? '?'}:${payload?.src?.port ?? '?'}`);
        lines.push(`  dst        : ${payload?.dst?.ip ?? '?'}:${payload?.dst?.port ?? '?'}`);
        break;
      case 'tcpSessionAborted':
        lines.push('  kind       : TcpSessionAbortedMidClose');
        lines.push(`  src        : ${payload?.src?.ip ?? '?'}:${payload?.src?.port ?? '?'}`);
        lines.push(`  dst        : ${payload?.dst?.ip ?? '?'}:${payload?.dst?.port ?? '?'}`);
        break;
      case 'tunDeviceSwapped':
        lines.push('  kind       : TunDeviceSwapped');
        lines.push(`  old_device : ${payload?.oldDevice ?? '?'}`);
        lines.push(`  new_device : ${payload?.newDevice ?? '?'}`);
        lines.push(`  old_address: ${payload?.oldAddress ?? '?'}`);
        lines.push(`  new_address: ${payload?.newAddress ?? '?'}`);
        break;
      case 'snifferConfigChanged':
        lines.push('  kind           : SnifferConfigChanged');
        lines.push(`  old_interfaces : [${(payload?.oldInterfaces ?? []).join(', ')}]`);
        lines.push(`  new_interfaces : [${(payload?.newInterfaces ?? []).join(', ')}]`);
        if (payload?.oldTimeout) lines.push(`  old_timeout    : ${JSON.stringify(payload.oldTimeout)}`);
        if (payload?.newTimeout) lines.push(`  new_timeout    : ${JSON.stringify(payload.newTimeout)}`);
        break;
      default:
        lines.push(`  kind       : ${eventKey ?? 'unknown'}`);
    }
  }

  lines.push('─'.repeat(60));
  return lines.join('\n');
}

function main() {
  // Load proto once — share between reflection and service
  const packageDef = protoLoader.loadSync(PROTO_FILES, LOADER_OPTIONS);
  const proto = grpc.loadPackageDefinition(packageDef) as any;

  const server = new grpc.Server();

  const serviceDef = proto.raptorgate.services.BackendEventService.service;

  server.addService(serviceDef, {
    pushEvents(
      call: grpc.ClientReadableStream<any>,
      callback: (err: grpc.ServiceError | null, response: {}) => void,
    ) {
      call.on('data', (rawEvent: any) => {
        console.log(formatEvent(rawEvent));
      });

      call.on('error', (err: Error) => {
        console.error('Stream error:', err.message);
      });

      call.on('end', () => {
        console.log('Client stream ended');
        callback(null, {});
      });
    },
  });

  server.bindAsync(
    `0.0.0.0:${PORT}`,
    grpc.ServerCredentials.createInsecure(),
    (err, port) => {
      if (err) {
        console.error('Failed to bind:', err);
        return;
      }
      console.log(`gRPC event server listening on 0.0.0.0:${port}`);
    },
  );
}

main();
