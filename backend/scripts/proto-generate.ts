import { spawnSync } from 'node:child_process';
import { existsSync, mkdirSync, rmSync } from 'node:fs';
import path from 'node:path';

const backendRoot = path.resolve(__dirname, '..');
const repositoryRoot = path.resolve(backendRoot, '..');
const protoRoot = path.join(repositoryRoot, 'proto');

const generatedRoot = path.join(
  backendRoot,
  'src',
  'infrastructure',
  'grpc',
  'generated',
);

const bundledProtocPath = path.join(backendRoot, '.protoc', 'bin', 'protoc');
const bundledProtocIncludePath = path.join(backendRoot, '.protoc', 'include');

const protocPath =
  process.env.PROTOC_PATH ??
  (existsSync(bundledProtocPath) ? bundledProtocPath : 'protoc');

const protocIncludePath =
  process.env.PROTOC_INCLUDE ??
  (existsSync(bundledProtocIncludePath)
    ? bundledProtocIncludePath
    : '/usr/include');

const tsProtoPluginPath = require.resolve('ts-proto/protoc-gen-ts_proto');

const tsProtoOptions = [
  'esModuleInterop=true',
  'env=node',
  'exportCommonSymbols=false',
  'oneof=unions',
  'snakeToCamel=keys_json',
  'useOptionals=messages',
  'nestJs=true',
  'outputServices=default',
];

function generate(): void {
  // NOTE: raptorgate.proto is currently inconsistent with events/firewall_events.proto.
  // Keep generation pinned to valid, actively used contracts until shared proto is fixed.
  const protoFiles = [
    path.join(protoRoot, 'common', 'common.proto'),
    path.join(protoRoot, 'config', 'config_models.proto'),
    path.join(protoRoot, 'config', 'config_service.proto'),
    path.join(protoRoot, 'control', 'validation_service.proto'),
    path.join(protoRoot, 'events', 'backend_events.proto'),
    path.join(protoRoot, 'events', 'firewall_events.proto'),
    path.join(protoRoot, 'services', 'event_service.proto'),
    path.join(protoRoot, 'services', 'query_service.proto'),
    path.join(protoRoot, 'telemetry', 'telemetry_models.proto'),
  ];

  rmSync(generatedRoot, { recursive: true, force: true });
  mkdirSync(generatedRoot, { recursive: true });

  const result = spawnSync(
    protocPath,
    [
      `--plugin=protoc-gen-ts_proto=${tsProtoPluginPath}`,
      `--proto_path=${protoRoot}`,
      `--proto_path=${protocIncludePath}`,
      `--ts_proto_out=${generatedRoot}`,
      `--ts_proto_opt=${tsProtoOptions.join(',')}`,
      ...protoFiles,
    ],
    {
      cwd: backendRoot,
      stdio: 'inherit',
    },
  );

  if (result.error) {
    throw new Error(`Proto generation failed: ${result.error.message}`);
  }

  if (result.status !== 0) {
    throw new Error('Proto generation failed');
  }

  console.log(`Generated gRPC types in ${generatedRoot}`);
}

generate();
