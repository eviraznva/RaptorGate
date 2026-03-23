import {
  TOKEN_SERVICE_TOKEN,
  type ITokenService,
  type TokenPayload,
} from '../ports/token-service.interface';
import { CreateRuleUseCase } from './create-rule.use-case';
import { RaptorLangValidationException } from 'src/domain/exceptions/raptor-lang-validation.exception';
import {
  RULES_REPOSITORY_TOKEN,
  type IRulesRepository,
} from 'src/domain/repositories/rules-repository';
import { join, resolve } from 'node:path';
import {
  ClientsModule,
  Transport,
  type ClientProviderOptions,
} from '@nestjs/microservices';
import {
  GrpcRaptorLangValidationService,
  RAPTOR_LANG_VALIDATION_GRPC_CLIENT_TOKEN,
} from 'src/infrastructure/adapters/grpc-raptor-lang-validation.service';
import { Test, type TestingModule } from '@nestjs/testing';
import {
  RAPTOR_LANG_VALIDATION_SERVICE_TOKEN,
  type IRaptorLangValidationService,
} from '../ports/raptor-lang-validation-service.interface';
import { type ChildProcess, spawn } from 'node:child_process';
import { mkdtempSync, rmSync, statSync } from 'node:fs';
import { tmpdir } from 'node:os';

const runIntegration = process.env.RUN_FIREWALL_INTEGRATION === '1';
const describeIntegration = runIntegration ? describe : describe.skip;

const repoRoot = resolve(__dirname, '../../../../');
const firewallBinaryPath = join(repoRoot, 'target', 'debug', 'ngfw');
const validationProtoPath = join(
  repoRoot,
  'proto',
  'control',
  'validation_service.proto',
);
const protoRoot = join(repoRoot, 'proto');

jest.setTimeout(30_000);

describeIntegration('CreateRuleUseCase integration with firewall validation', () => {
  let moduleRef: TestingModule;
  let useCase: CreateRuleUseCase;
  let firewallProcess: ChildProcess | null = null;
  let runtimeDir: string;
  let firewallLogs = '';

  const repository: jest.Mocked<IRulesRepository> = {
    save: jest.fn(),
    findById: jest.fn(),
    findAll: jest.fn(),
    finfByName: jest.fn(),
    delete: jest.fn(),
  };

  const tokenService: jest.Mocked<ITokenService> = {
    generateAccessToken: jest.fn(),
    generateRefreshToken: jest.fn(),
    generateTokenPair: jest.fn(),
    verifyAccessToken: jest.fn(),
    decodeAccessToken: jest.fn(),
  };

  const validClaims: TokenPayload = {
    sub: 'user-1',
    username: 'marek',
  };

  beforeEach(async () => {
    jest.clearAllMocks();
    firewallLogs = '';

    runtimeDir = mkdtempSync(join(tmpdir(), 'raptorgate-fw-it-'));
    const firewallSocketPath = join(runtimeDir, 'control-plane.sock');

    firewallProcess = spawnFirewall(runtimeDir, firewallSocketPath);
    await waitForSocket(firewallSocketPath);

    moduleRef = await Test.createTestingModule({
      imports: [createValidationClientModule(firewallSocketPath)],
      providers: [
        CreateRuleUseCase,
        GrpcRaptorLangValidationService,
        {
          provide: RULES_REPOSITORY_TOKEN,
          useValue: repository,
        },
        {
          provide: TOKEN_SERVICE_TOKEN,
          useValue: tokenService,
        },
        {
          provide: RAPTOR_LANG_VALIDATION_SERVICE_TOKEN,
          useExisting: GrpcRaptorLangValidationService,
        },
      ],
    }).compile();

    await moduleRef.init();
    useCase = moduleRef.get(CreateRuleUseCase);
  });

  afterEach(async () => {
    if (moduleRef) {
      await moduleRef.close();
    }

    await stopFirewall();
    rmSync(runtimeDir, { recursive: true, force: true });
  });

  it('saves a rule when the connected firewall accepts valid RaptorLang', async () => {
    const dto = {
      name: 'Allow HTTPS',
      description: 'valid nested firewall rule',
      zonePairId: 'zone-pair-1',
      isActive: true,
      content:
        'match ip_ver { = v4 : match protocol { = tcp : match dst_port { = 443 : verdict allow _ : verdict drop } } }',
      priority: 100,
      accessToken: 'valid-token',
    };

    tokenService.decodeAccessToken.mockReturnValue(validClaims);
    repository.finfByName.mockResolvedValue(null);

    await expect(useCase.execute(dto)).resolves.toBeUndefined();

    expect(repository.save).toHaveBeenCalledTimes(1);
    expect(repository.save.mock.calls[0][0].getContent()).toBe(dto.content);
  });

  it('rejects a rule when the connected firewall reports invalid RaptorLang', async () => {
    const dto = {
      name: 'Broken Rule',
      description: 'invalid syntax',
      zonePairId: 'zone-pair-1',
      isActive: true,
      content: 'match protocol { = tcp verdict allow }',
      priority: 50,
      accessToken: 'valid-token',
    };

    tokenService.decodeAccessToken.mockReturnValue(validClaims);
    repository.finfByName.mockResolvedValue(null);

    await expect(useCase.execute(dto)).rejects.toBeInstanceOf(
      RaptorLangValidationException,
    );
    expect(repository.save).not.toHaveBeenCalled();
  });

  function createValidationClientModule(
    firewallSocketPath: string,
  ): ClientProviderOptions {
    return ClientsModule.register([
      {
        name: RAPTOR_LANG_VALIDATION_GRPC_CLIENT_TOKEN,
        transport: Transport.GRPC,
        options: {
          package: 'raptorgate.control',
          protoPath: validationProtoPath,
          loader: {
            includeDirs: [protoRoot],
          },
          url: `unix://${firewallSocketPath}`,
        },
      },
    ]);
  }

  function spawnFirewall(
    tmpRuntimeDir: string,
    firewallSocketPath: string,
  ): ChildProcess {
    const child = spawn(firewallBinaryPath, [], {
      cwd: repoRoot,
      env: {
        ...process.env,
        DISABLE_DATA_PLANE: 'true',
        GRPC_SOCKET_PATH: join(tmpRuntimeDir, 'backend.sock'),
        CONTROL_PLANE_GRPC_SOCKET_PATH: firewallSocketPath,
        REDB_SNAPSHOT_PATH: join(tmpRuntimeDir, 'snapshot.redb'),
        RAPTORGATE_PKI_DIR: join(tmpRuntimeDir, 'pki'),
      },
      stdio: ['ignore', 'pipe', 'pipe'],
    });

    child.stdout?.on('data', (chunk: Buffer | string) => {
      firewallLogs += chunk.toString();
    });
    child.stderr?.on('data', (chunk: Buffer | string) => {
      firewallLogs += chunk.toString();
    });

    return child;
  }

  async function waitForSocket(socketPath: string): Promise<void> {
    const deadline = Date.now() + 10_000;

    while (Date.now() < deadline) {
      if (firewallProcess?.exitCode !== null) {
        throw new Error(
          `Firewall exited before creating validation socket.\n${firewallLogs}`,
        );
      }

      try {
        const stats = statSync(socketPath);
        if (stats.isSocket()) {
          return;
        }
      } catch {}

      await new Promise((resolveDelay) => setTimeout(resolveDelay, 100));
    }

    throw new Error(
      `Timed out waiting for firewall validation socket: ${socketPath}\n${firewallLogs}`,
    );
  }

  async function stopFirewall(): Promise<void> {
    if (!firewallProcess) {
      return;
    }

    const child = firewallProcess;
    firewallProcess = null;

    if (child.exitCode !== null) {
      child.stdout?.destroy();
      child.stderr?.destroy();
      return;
    }

    child.kill('SIGTERM');

    await Promise.race([
      new Promise<void>((resolveExit) => {
        child.once('exit', () => resolveExit());
      }),
      new Promise<void>((resolveTimeout) =>
        setTimeout(() => {
          if (child.exitCode === null) {
            child.kill('SIGKILL');
          }
          resolveTimeout();
        }, 3_000),
      ),
    ]);

    child.stdout?.destroy();
    child.stderr?.destroy();
  }
});
