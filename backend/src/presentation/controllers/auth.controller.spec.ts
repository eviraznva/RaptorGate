import { RefreshTokenUseCase } from "../../application/use-cases/refresh-token.use-case.js";
import { LogoutUserUseCase } from "../../application/use-cases/logout-user.use-case.js";
import { LoginUserUseCase } from "../../application/use-cases/login-user.use-case.js";
import { AuthController } from "./auth.controller.js";
import { jest } from "@jest/globals";
import { TestingModule, Test } from "@nestjs/testing";
import { ConfigService } from "@nestjs/config";

describe("AuthController", () => {
	let controller: AuthController;
	let loginUserUseCase: jest.Mocked<LoginUserUseCase>;
	let refreshTokenUseCase: jest.Mocked<RefreshTokenUseCase>;
	let configService: jest.Mocked<ConfigService>;
	// Mock obiektu odpowiedzi Express do testowania ciasteczek
	let mockResponse: jest.Mocked<Partial<Response>>;
	beforeEach(async () => {
		mockResponse = {
			cookie: jest.fn(),
		};
		loginUserUseCase = {
			execute: jest.fn(),
		} as any;
		refreshTokenUseCase = {
			execute: jest.fn(),
		} as any;
		configService = {
			get: jest.fn(),
		} as any;
		const module: TestingModule = await Test.createTestingModule({
			controllers: [AuthController],
			providers: [
				{
					provide: LoginUserUseCase,
					useValue: loginUserUseCase,
				},
				{
					provide: RefreshTokenUseCase,
					useValue: refreshTokenUseCase,
				},
				{
					provide: ConfigService,
					useValue: configService,
				},
				{
					provide: LogoutUserUseCase,
					useValue: { execute: jest.fn() },
				},
			],
		}).compile();
		controller = module.get<AuthController>(AuthController);
	});
	afterEach(() => {
		jest.clearAllMocks();
	});
	it("should be defined", () => {
		expect(controller).toBeDefined();
	});
	describe("login", () => {
		it("should authenticate user, set cookie and return access token", async () => {
			// Przygotowanie danych testowych
			const loginDto = { username: "testuser", password: "password123" };
			const expectedResponse = {
				accessToken: "mock-access-token",
				refreshToken: "mock-refresh-token",
				// Inne potencjalne dane z login response
			};
			// Zachowanie mocków
			loginUserUseCase.execute.mockResolvedValue(expectedResponse);
			configService.get.mockImplementation((key) => {
				if (key === "NODE_ENV") return "development";
				return undefined;
			});
			// Wykonanie testowanej metody
			const result = await controller.login(loginDto, mockResponse as Response);
			// Asercje (sprawdzenia)
			expect(loginUserUseCase.execute).toHaveBeenCalledWith({
				username: "testuser",
				password: "password123",
			});
			expect(mockResponse.cookie).toHaveBeenCalledWith(
				"refresh_token",
				"mock-refresh-token",
				{
					httpOnly: true,
					secure: true, // poniewaz NODE_ENV === 'development'
					sameSite: "strict",
					maxAge: 3600000,
					path: "/auth/refresh",
				},
			);
			// Wynik nie powinien zawierać refreshTokena, bo ten ląduje tylko w ciastku
			expect(result).toEqual({ accessToken: "mock-access-token" });
		});
	});
	describe("refresh", () => {
		it("should refresh access token WITHOUT rotating refresh token (cookie not set)", async () => {
			const accessToken = "old-access-token";
			const refreshToken = "valid-refresh-token";
			const expectedResponse = {
				accessToken: "new-access-token",
				// Brak refreshToken w odpowiedzi z UseCase
			};
			refreshTokenUseCase.execute.mockResolvedValue(expectedResponse);
			const result = await controller.refresh(
				accessToken,
				refreshToken,
				mockResponse as Response,
			);
			expect(refreshTokenUseCase.execute).toHaveBeenCalledWith({
				accessToken,
				refreshToken,
			});
			// Sprawdzamy czy metoda cookie NIE została wywołana, bo nie dostaliśmy nowego od UseCase
			expect(mockResponse.cookie).not.toHaveBeenCalled();
			expect(result).toEqual({ accessToken: "new-access-token" });
		});
		it("should refresh access token AND set new cookie when refresh token is rotated", async () => {
			const accessToken = "old-access-token";
			const refreshToken = "valid-refresh-token";
			const expectedResponse = {
				accessToken: "new-access-token",
				refreshToken: "rotated-refresh-token", // Use case zwrócił nowy RT
			};
			refreshTokenUseCase.execute.mockResolvedValue(expectedResponse);
			configService.get.mockReturnValue("development");
			const result = await controller.refresh(
				accessToken,
				refreshToken,
				mockResponse as Response,
			);
			expect(refreshTokenUseCase.execute).toHaveBeenCalledWith({
				accessToken,
				refreshToken,
			});
			// Tutaj oczekujemy, że zostanie zapisane ciastko z NOWYM 'rotated-refresh-token'
			// UWAGA: Test ten nie przejdzie na obecnym kodzie AuthController. W linii 122 jest błąd:
			// res.cookie('refresh_token', refreshToken, {...}) (przekazujesz stary zamiast useCase.refreshToken)
			expect(mockResponse.cookie).toHaveBeenCalledWith(
				"refresh_token",
				"rotated-refresh-token",
				expect.any(Object),
			);
			expect(result).toEqual({ accessToken: "new-access-token" });
		});
	});
});
