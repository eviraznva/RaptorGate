import {
  RAPTOR_LANG_VALIDATION_SERVICE_TOKEN,
  type IRaptorLangValidationService,
} from '../ports/raptor-lang-validation-service.interface';
import {
  TOKEN_SERVICE_TOKEN,
  type ITokenService,
  type TokenPayload,
} from '../ports/token-service.interface';
import {
  RULES_REPOSITORY_TOKEN,
  type IRulesRepository,
} from 'src/domain/repositories/rules-repository';
import { CreateRuleUseCase } from './create-rule.use-case';
import { AccessTokenIsInvalidException } from 'src/domain/exceptions/acces-token-is-invalid.exception';
import { RaptorLangValidationException } from 'src/domain/exceptions/raptor-lang-validation.exception';
import { EntityAlreadyExistsException } from 'src/domain/exceptions/entity-already-exists-exception';
import { FirewallRule } from 'src/domain/entities/firewall-rule.entity';
import { Priority } from 'src/domain/value-objects/priority.vo';
import { Test, TestingModule } from '@nestjs/testing';

describe('CreateRuleUseCase', () => {
  let useCase: CreateRuleUseCase;

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

  const raptorLangValidationService: jest.Mocked<IRaptorLangValidationService> =
    {
      validateRaptorLang: jest.fn(),
    };

  const validClaims: TokenPayload = {
    sub: 'user-1',
    username: 'marek',
  };

  const createExistingRule = (): FirewallRule =>
    FirewallRule.create(
      'rule-1',
      'Allow HTTPS',
      'existing rule',
      'zone-pair-1',
      true,
      'match protocol { = tcp : verdict allow }',
      Priority.create(10),
      new Date('2026-03-20T23:11:43.970Z'),
      new Date('2026-03-20T23:11:43.970Z'),
      'user-1',
    );

  beforeEach(async () => {
    jest.clearAllMocks();

    const module: TestingModule = await Test.createTestingModule({
      providers: [
        CreateRuleUseCase,
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
          useValue: raptorLangValidationService,
        },
      ],
    }).compile();

    useCase = module.get(CreateRuleUseCase);
  });

  it('validates RaptorLang content and saves rule for a valid payload', async () => {
    const dto = {
      name: 'Allow HTTPS',
      description: 'allow outbound tls',
      zonePairId: 'zone-pair-1',
      isActive: true,
      content:
        'match ip_ver { = v4 : match protocol { = tcp : match dst_port { = 443 : verdict allow _ : verdict drop } } }',
      priority: 100,
      accessToken: 'valid-token',
    };

    tokenService.decodeAccessToken.mockReturnValue(validClaims);
    repository.finfByName.mockResolvedValue(null);
    raptorLangValidationService.validateRaptorLang.mockResolvedValue();

    await useCase.execute(dto);

    expect(tokenService.decodeAccessToken).toHaveBeenCalledWith(
      dto.accessToken,
    );
    expect(repository.finfByName).toHaveBeenCalledWith(dto.name);
    expect(raptorLangValidationService.validateRaptorLang).toHaveBeenCalledWith(
      dto.content,
    );
    expect(repository.save).toHaveBeenCalledTimes(1);

    const savedRule = repository.save.mock.calls[0][0];
    expect(savedRule).toBeInstanceOf(FirewallRule);
    expect(savedRule.getName()).toBe(dto.name);
    expect(savedRule.getDescription()).toBe(dto.description);
    expect(savedRule.getZonePairId()).toBe(dto.zonePairId);
    expect(savedRule.getIsActive()).toBe(dto.isActive);
    expect(savedRule.getContent()).toBe(dto.content);
    expect(savedRule.getPriority().getValue()).toBe(dto.priority);
    expect(savedRule.getCreatedBy()).toBe(validClaims.sub);
  });

  it('propagates RaptorLang validation errors and does not save the rule', async () => {
    const dto = {
      name: 'Broken Rule',
      description: 'invalid RaptorLang',
      zonePairId: 'zone-pair-1',
      isActive: true,
      content: 'match protocol { = tcp verdict allow }',
      priority: 50,
      accessToken: 'valid-token',
    };
    const validationError = new RaptorLangValidationException(
      'Unexpected token at 1:26',
    );

    tokenService.decodeAccessToken.mockReturnValue(validClaims);
    repository.finfByName.mockResolvedValue(null);
    raptorLangValidationService.validateRaptorLang.mockRejectedValue(
      validationError,
    );

    await expect(useCase.execute(dto)).rejects.toBe(validationError);

    expect(raptorLangValidationService.validateRaptorLang).toHaveBeenCalledWith(
      dto.content,
    );
    expect(repository.save).not.toHaveBeenCalled();
  });

  it('throws for invalid access token before RaptorLang validation', async () => {
    const dto = {
      name: 'Allow DNS',
      description: 'allow dns traffic',
      zonePairId: 'zone-pair-2',
      isActive: true,
      content: 'match protocol { = udp : verdict allow }',
      priority: 20,
      accessToken: 'bad-token',
    };

    tokenService.decodeAccessToken.mockReturnValue(null);

    await expect(useCase.execute(dto)).rejects.toBeInstanceOf(
      AccessTokenIsInvalidException,
    );

    expect(repository.finfByName).not.toHaveBeenCalled();
    expect(
      raptorLangValidationService.validateRaptorLang,
    ).not.toHaveBeenCalled();
    expect(repository.save).not.toHaveBeenCalled();
  });

  it('throws when rule name already exists and skips RaptorLang validation', async () => {
    const dto = {
      name: 'Allow HTTPS',
      description: 'duplicate rule',
      zonePairId: 'zone-pair-1',
      isActive: true,
      content: 'match protocol { = tcp : verdict allow }',
      priority: 10,
      accessToken: 'valid-token',
    };

    tokenService.decodeAccessToken.mockReturnValue(validClaims);
    repository.finfByName.mockResolvedValue(createExistingRule());

    await expect(useCase.execute(dto)).rejects.toBeInstanceOf(
      EntityAlreadyExistsException,
    );

    expect(repository.finfByName).toHaveBeenCalledWith(dto.name);
    expect(
      raptorLangValidationService.validateRaptorLang,
    ).not.toHaveBeenCalled();
    expect(repository.save).not.toHaveBeenCalled();
  });
});
