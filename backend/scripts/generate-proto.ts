import { spawnSync } from 'node:child_process';
import { existsSync, mkdirSync, readdirSync, rmSync } from 'node:fs';
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

function collectProtoFiles(rootDir: string): string[] {
  const files: string[] = [];

  function visit(currentDir: string): void {
    for (const entry of readdirSync(currentDir, { withFileTypes: true })) {
      const fullPath = path.join(currentDir, entry.name);

      if (entry.isDirectory()) {
        visit(fullPath);
        continue;
      }

      if (entry.isFile() && entry.name.endsWith('.proto')) {
        files.push(fullPath);
      }
    }
  }

  visit(rootDir);
  return files.sort((a, b) => a.localeCompare(b));
}

const targets: GenerationTarget[] = [
  {
    outDir: path.join(generatedRoot),
    protoFiles: collectProtoFiles(protoRoot),
    options: [...baseOptions, 'nestJs=true', 'outputServices=default'],
  },
];

function prepareOutputDirectory(target: GenerationTarget): void {
  rmSync(target.outDir, { recursive: true, force: true });
  mkdirSync(target.outDir, { recursive: true });
}

function generateTarget(target: GenerationTarget): void {
  if (target.protoFiles.length === 0) {
    throw new Error(`No .proto files found under ${protoRoot}`);
  }

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
