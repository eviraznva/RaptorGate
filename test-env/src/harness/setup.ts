import * as grpc from '@grpc/grpc-js';
import * as protoLoader from '@grpc/proto-loader';
import path from 'node:path';
import { startSshTunnel, type TunnelReadyContext } from '../ssh-tunnel';
import { eventCollector } from './event-collector';
import {
  setClient,
  setSnapshotClient,
  type FirewallConfigSnapshotServiceClient,
  type FirewallQueryServiceClient,
} from './grpc-client';

const PROTO_ROOT = path.resolve(__dirname, '../../../proto');
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

const PORT = 50052;

let readyPromise: Promise<void>;
let readyResolve: () => void;

function initReadyPromise(): Promise<void> {
  readyPromise = new Promise<void>((resolve) => {
    readyResolve = resolve;
  });
  return readyPromise;
}

export function initializeHarness(): void {
  const promise = initReadyPromise();

  const packageDef = protoLoader.loadSync(PROTO_FILES, LOADER_OPTIONS);
  const proto = grpc.loadPackageDefinition(packageDef) as any;

  const server = new grpc.Server();
  const serviceDef = proto.raptorgate.services.BackendEventService.service;

  server.addService(serviceDef, {
    pushEvents(
      call: grpc.ServerReadableStream<any, any>,
      callback: (err: grpc.ServiceError | null, response: {}) => void,
    ) {
      call.on('data', (rawEvent: any) => {
        eventCollector.push(rawEvent);
      });

      call.on('error', (err: Error) => {
        console.error('[setup] Stream error:', err.message);
      });

      call.on('end', () => {
        console.log('[setup] Client stream ended');
        callback(null, {});
      });
    },
  });

  server.bindAsync(
    `0.0.0.0:${PORT}`,
    grpc.ServerCredentials.createInsecure(),
    (err, port) => {
      if (err) {
        console.error('[setup] Failed to bind:', err);
        return;
      }
      console.log(`[setup] gRPC event server listening on 0.0.0.0:${port}`);
      startSshTunnel(server, {
        onReady: ({ queryClient, snapshotClient }: TunnelReadyContext) => {
          setClient(queryClient as FirewallQueryServiceClient);
          setSnapshotClient(snapshotClient as FirewallConfigSnapshotServiceClient);
          console.log('[setup] System ready — event server + query/snapshot clients connected');
          readyResolve();
        },
      });
    },
  );
}

export async function waitForReady(): Promise<void> {
  if (!readyPromise) {
    throw new Error('Harness not initialized — call initializeHarness() first');
  }
  return readyPromise;
}
