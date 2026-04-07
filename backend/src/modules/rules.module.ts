import {
	GrpcRaptorLangValidationService,
	RAPTOR_LANG_VALIDATION_GRPC_CLIENT_TOKEN,
} from "../infrastructure/adapters/grpc-raptor-lang-validation.service.js";
import { RAPTOR_LANG_VALIDATION_SERVICE_TOKEN } from "../application/ports/raptor-lang-validation-service.interface.js";
import { JsonRuleRepository } from "../infrastructure/persistence/repositories/json-rule.repository.js";
import { GetAllRulesUseCase } from "../application/use-cases/get-all-rules.use-case.js";
import { TOKEN_SERVICE_TOKEN } from "../application/ports/token-service.interface.js";
import { CreateRuleUseCase } from "../application/use-cases/create-rule.use-case.js";
import { DeleteRuleUseCase } from "../application/use-cases/delete-rule.use-case.js";
import { RULES_REPOSITORY_TOKEN } from "../domain/repositories/rules-repository.js";
import { EditRuleUseCase } from "../application/use-cases/edit-rule.use-case.js";
import { RulesController } from "../presentation/controllers/rule.controller.js";
import { TokenService } from "../infrastructure/adapters/jwt-token.service.js";
import { FileStore } from "../infrastructure/persistence/json/file-store.js";
import { Mutex } from "../infrastructure/persistence/json/file-mutex.js";
import { ClientsModule, Transport } from "@nestjs/microservices";
import { Env } from "../shared/config/env.validation.js";
import { ConfigService } from "@nestjs/config";
import { JwtService } from "@nestjs/jwt";
import { Module } from "@nestjs/common";
import { join } from "node:path";

@Module({
	imports: [
		ClientsModule.registerAsync([
			{
				name: RAPTOR_LANG_VALIDATION_GRPC_CLIENT_TOKEN,
				useFactory: (configService: ConfigService<Env, true>) => {
					const backendSocketPath = configService.get("GRPC_SOCKET_PATH", {
						infer: true,
					});

					const firewallSocketPath = configService.get(
						"FIREWALL_GRPC_SOCKET_PATH",
						{
							infer: true,
						},
					);

					const resolveGrpcUrl = (path: string): string =>
						path.startsWith("unix://")
							? path
							: `unix://${join(process.cwd(), path)}`;

					const backendGrpcUrl = resolveGrpcUrl(backendSocketPath);
					const firewallGrpcUrl = resolveGrpcUrl(firewallSocketPath);

					if (backendGrpcUrl === firewallGrpcUrl) {
						throw new Error(
							"FIREWALL_GRPC_SOCKET_PATH must point to firewall validation service and cannot equal GRPC_SOCKET_PATH.",
						);
					}

					const grpcUrl = firewallGrpcUrl;

					return {
						transport: Transport.GRPC,
						options: {
							package: "raptorgate.control",
							protoPath: join(
								process.cwd(),
								"..",
								"proto",
								"control",
								"validation_service.proto",
							),
							loader: {
								includeDirs: [join(process.cwd(), "..", "proto")],
							},
							url: grpcUrl,
						},
					};
				},
				inject: [ConfigService],
			},
		]),
	],
	controllers: [RulesController],
	providers: [
		GetAllRulesUseCase,
		EditRuleUseCase,
		DeleteRuleUseCase,
		CreateRuleUseCase,
		FileStore,
		Mutex,
		{
			provide: TOKEN_SERVICE_TOKEN,
			useClass: TokenService,
		},
		{
			provide: RAPTOR_LANG_VALIDATION_SERVICE_TOKEN,
			useClass: GrpcRaptorLangValidationService,
		},
		{
			provide: RULES_REPOSITORY_TOKEN,
			useClass: JsonRuleRepository,
		},
		JwtService,
	],
})
export class RulesModule {}
