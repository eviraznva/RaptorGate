import path from 'node:path';
import * as grpc from '@grpc/grpc-js';
import * as protoLoader from '@grpc/proto-loader';
import { Event } from './generated/events/firewall_events';

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

function main() {
  // Load proto once — share between reflection and service
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
        // console.log(formatEvent(rawEvent));
		const event = Event.fromJSON(rawEvent)

		console.log(event);
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
