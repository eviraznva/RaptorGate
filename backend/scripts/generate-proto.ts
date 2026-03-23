import { spawnSync } from 'node:child_process';
import { mkdirSync, rmSync } from 'node:fs';
import { existsSync } from 'node:fs';
import path from 'node:path';

type GenerationTarget = {
  outDir: string;
  protoFiles: string[];
  options: string[];
};

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

const baseOptions = [
  'esModuleInterop=true',
  'env=node',
  'exportCommonSymbols=false',
  'oneof=unions',
  'snakeToCamel=keys_json',
  'useOptionals=messages',
];

const targets: GenerationTarget[] = [
  {
    outDir: path.join(generatedRoot),
    protoFiles: [
      path.join(protoRoot, 'common', 'common.proto'),
      path.join(protoRoot, 'config', 'config_models.proto'),
      path.join(protoRoot, 'config', 'config_service.proto'),
      path.join(protoRoot, 'events', 'backend_events.proto'),
      path.join(protoRoot, 'events', 'firewall_events.proto'),
      path.join(protoRoot, 'control', 'validation_service.proto'),
      path.join(protoRoot, 'telemetry', 'telemetry_models.proto'),
      path.join(protoRoot, 'raptorgate.proto'),
    ],
    options: [...baseOptions, 'nestJs=true', 'outputServices=default'],
  },
];

function prepareOutputDirectory(target: GenerationTarget): void {
  rmSync(target.outDir, { recursive: true, force: true });
  mkdirSync(target.outDir, { recursive: true });
}

function generateTarget(target: GenerationTarget): void {
  prepareOutputDirectory(target);

  const result = spawnSync(
    protocPath,
    [
      `--plugin=protoc-gen-ts_proto=${tsProtoPluginPath}`,
      `--proto_path=${protoRoot}`,
      `--proto_path=${protocIncludePath}`,
      `--ts_proto_out=${target.outDir}`,
      `--ts_proto_opt=${target.options.join(',')}`,
      ...target.protoFiles,
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
}

function main(): void {
  mkdirSync(generatedRoot, { recursive: true });

  for (const target of targets) {
    generateTarget(target);
  }

  console.log(`Generated gRPC types in ${generatedRoot}`);
}

main();
