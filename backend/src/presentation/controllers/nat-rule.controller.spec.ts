import { GetAllNatRulesUseCase } from "../../application/use-cases/get-all-nat-rules.use-case.js";
import { CreateNatRuleUseCase } from "../../application/use-cases/create-nat-rule.use-case.js";
import { DeleteNatRuleUseCase } from "../../application/use-cases/delete-nat-rule.use-case.js";
import { EditNatRuleUseCase } from "../../application/use-cases/edit-nat-rule.use-case.js";
import { NatRuleController } from "./nat-rule.controller.js";
import { Test, TestingModule } from "@nestjs/testing";
import { jest } from "@jest/globals";

describe("NatRuleController", () => {
	let controller: NatRuleController;

	const createNatRuleUseCase = {
		execute: jest.fn(),
	};

	const getAllNatRulesUseCase = {
		execute: jest.fn(),
	};

	const editNatRuleUseCase = {
		execute: jest.fn(),
	};

	const deleteNatRuleUseCase = {
		execute: jest.fn(),
	};

	beforeEach(async () => {
		createNatRuleUseCase.execute.mockReset();
		getAllNatRulesUseCase.execute.mockReset();
		editNatRuleUseCase.execute.mockReset();
		deleteNatRuleUseCase.execute.mockReset();

		const module: TestingModule = await Test.createTestingModule({
			controllers: [NatRuleController],
			providers: [
				{
					provide: CreateNatRuleUseCase,
					useValue: createNatRuleUseCase,
				},
				{
					provide: GetAllNatRulesUseCase,
					useValue: getAllNatRulesUseCase,
				},
				{
					provide: EditNatRuleUseCase,
					useValue: editNatRuleUseCase,
				},
				{
					provide: DeleteNatRuleUseCase,
					useValue: deleteNatRuleUseCase,
				},
			],
		}).compile();

		controller = module.get(NatRuleController);
	});

	it("createNatRule calls use-case with dto and access token", async () => {
		createNatRuleUseCase.execute.mockResolvedValue(undefined);

		const dto = {
			type: "SNAT",
			isActive: true,
			sourceIp: "192.168.1.10",
			destinationIp: null,
			sourcePort: null,
			destinationPort: null,
			translatedIp: "172.16.0.20",
			translatedPort: null,
			priority: 10,
		};
		const accessToken = "token-value";

		await controller.createNatRule(dto, accessToken);

		expect(createNatRuleUseCase.execute).toHaveBeenCalledWith({
			...dto,
			accessToken,
		});
	});

	it("getAllNatRules returns use-case response", async () => {
		const result = { natRules: [] };
		getAllNatRulesUseCase.execute.mockResolvedValue(result);

		await expect(controller.getAllNatRules()).resolves.toEqual(result);
		expect(getAllNatRulesUseCase.execute).toHaveBeenCalledTimes(1);
	});

	it("editNatRule calls use-case with route id merged into dto", async () => {
		editNatRuleUseCase.execute.mockResolvedValue(undefined);

		const id = "rule-id-123";
		const dto = {
			priority: 25,
			isActive: false,
		};

		await controller.editNatRule(dto, id);

		expect(editNatRuleUseCase.execute).toHaveBeenCalledWith({
			id,
			...dto,
		});
	});

	it("deleteNatRule calls use-case with id", async () => {
		deleteNatRuleUseCase.execute.mockResolvedValue(undefined);

		const id = "rule-id-321";
		await controller.deleteNatRule(id);

		expect(deleteNatRuleUseCase.execute).toHaveBeenCalledWith(id);
	});
});
