export interface IRaptorLangValidationService {
	validateRaptorLang(content: string): Promise<void>;
}

export const RAPTOR_LANG_VALIDATION_SERVICE_TOKEN = Symbol(
	"RAPTOR_LANG_VALIDATION_SERVICE_TOKEN",
);
