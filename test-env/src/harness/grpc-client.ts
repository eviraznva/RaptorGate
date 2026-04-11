import * as grpc from '@grpc/grpc-js';
import * as protoLoader from '@grpc/proto-loader';
import path from 'node:path';

const PROTO_ROOT = path.resolve(__dirname, '../../../proto');
const PROTO_FILES = [
  path.join(PROTO_ROOT, 'services', 'query_service.proto'),
  path.join(PROTO_ROOT, 'config', 'config_models.proto'),
  path.join(PROTO_ROOT, 'common', 'common.proto'),
];

const LOADER_OPTIONS = {
  keepCase: true,
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

let _client: FirewallQueryServiceClient | null = null;

export function setClient(client: FirewallQueryServiceClient): void {
  _client = client;
}

export function getClient(): FirewallQueryServiceClient {
  if (!_client) {
    throw new Error('gRPC query client not initialized — has setup.ts preload run?');
  }
  return _client;
}

export function createQueryClient(socketPath: string): FirewallQueryServiceClient {
  return new proto.raptorgate.services.FirewallQueryService(
    `unix:${socketPath}`,
    grpc.credentials.createInsecure(),
  );
}
