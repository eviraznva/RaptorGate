import * as grpc from '@grpc/grpc-js';
import * as protoLoader from '@grpc/proto-loader';
import path from 'node:path';

const PROTO_ROOT = path.resolve(__dirname, '../../../proto');
const PROTO_FILES = [
  path.join(PROTO_ROOT, 'services', 'query_service.proto'),
  path.join(PROTO_ROOT, 'services', 'config_snapshot_service.proto'),
  path.join(PROTO_ROOT, 'config', 'config_models.proto'),
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

const packageDef = protoLoader.loadSync(PROTO_FILES, LOADER_OPTIONS);
const proto = grpc.loadPackageDefinition(packageDef) as any;

export type FirewallQueryServiceClient = InstanceType<
  typeof proto.raptorgate.services.FirewallQueryService
>;

export type FirewallConfigSnapshotServiceClient = InstanceType<
  typeof proto.raptorgate.services.FirewallConfigSnapshotService
>;

let _client: FirewallQueryServiceClient | null = null;
let _snapshotClient: FirewallConfigSnapshotServiceClient | null = null;

export function setClient(client: FirewallQueryServiceClient): void {
  _client = client;
}

export function setSnapshotClient(client: FirewallConfigSnapshotServiceClient): void {
  _snapshotClient = client;
}

export function getClient(): FirewallQueryServiceClient {
  if (!_client) {
    throw new Error('gRPC query client not initialized — has setup.ts preload run?');
  }
  return _client;
}

export function getSnapshotClient(): FirewallConfigSnapshotServiceClient {
  if (!_snapshotClient) {
    throw new Error('gRPC snapshot client not initialized — has setup.ts preload run?');
  }
  return _snapshotClient;
}

export function createQueryClient(socketPath: string): FirewallQueryServiceClient {
  return new proto.raptorgate.services.FirewallQueryService(
    `unix:${socketPath}`,
    grpc.credentials.createInsecure(),
  );
}

export function createSnapshotClient(socketPath: string): FirewallConfigSnapshotServiceClient {
  return new proto.raptorgate.services.FirewallConfigSnapshotService(
    `unix:${socketPath}`,
    grpc.credentials.createInsecure(),
  );
}
