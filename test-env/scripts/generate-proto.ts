import { spawnSync } from 'node:child_process';
import { mkdirSync, rmSync } from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const testEnvRoot = path.resolve(__dirname, '..');
const repoRoot = path.resolve(testEnvRoot, '..');
const protoRoot = path.join(repoRoot, 'proto');
const generatedOut = path.join(testEnvRoot, 'src', 'generated');

const tsProtoPlugin = require.resolve('ts-proto/protoc-gen-ts_proto');

const options = [
  'esModuleInterop=true',
  'env=node',
  'exportCommonSymbols=false',
  'oneof=unions',
  'snakeToCamel=keys_json',
  'useOptionals=messages',
];

// Only the protos needed for the event service
const protoFiles = [
  path.join(protoRoot, 'common', 'common.proto'),
  path.join(protoRoot, 'events', 'firewall_events.proto'),
  path.join(protoRoot, 'services', 'event_service.proto'),
];

function main() {
  rmSync(generatedOut, { recursive: true, force: true });
  mkdirSync(generatedOut, { recursive: true });

  const result = spawnSync(
    'protoc',
    [
      `--plugin=protoc-gen-ts_proto=${tsProtoPlugin}`,
      `--proto_path=${protoRoot}`,
      `--ts_proto_out=${generatedOut}`,
      `--ts_proto_opt=${options.join(',')}`,
      ...protoFiles,
    ],
    { cwd: testEnvRoot, stdio: 'inherit' },
  );

  if (result.error) {
    throw new Error(`Proto generation failed: ${result.error.message}`);
  }
  if (result.status !== 0) {
    throw new Error('protoc exited with non-zero status');
  }

  console.log(`Generated gRPC types in ${generatedOut}`);
}

main();
