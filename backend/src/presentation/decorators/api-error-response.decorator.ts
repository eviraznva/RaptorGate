import {
	getSchemaPath,
	ApiExtraModels,
	ApiBadRequestResponse,
	ApiUnauthorizedResponse,
	ApiForbiddenResponse,
	ApiNotFoundResponse,
	ApiConflictResponse,
	ApiTooManyRequestsResponse,
	ApiInternalServerErrorResponse,
} from "@nestjs/swagger";
import { ErrorEnvelopeDto } from "../dtos/api-envelope.dto.js";
import { applyDecorators } from "@nestjs/common";

const err = (status: number, message: string, error: string) => ({
	allOf: [
		{ $ref: getSchemaPath(ErrorEnvelopeDto) },
		{
			properties: {
				statusCode: { example: status },
				message: { example: message },
				error: { example: error },
			},
		},
	],
});

export const ApiError400 = (m = "Validation failed") =>
	applyDecorators(
		ApiExtraModels(ErrorEnvelopeDto),
		ApiBadRequestResponse({ schema: err(400, m, "Bad Request") }),
	);

export const ApiError401 = (m = "Missing or invalid token") =>
	applyDecorators(
		ApiExtraModels(ErrorEnvelopeDto),
		ApiUnauthorizedResponse({ schema: err(401, m, "Unauthorized") }),
	);

export const ApiError403 = (m = "Forbidden: insufficient permissions") =>
	applyDecorators(
		ApiExtraModels(ErrorEnvelopeDto),
		ApiForbiddenResponse({ schema: err(403, m, "Forbidden") }),
	);

export const ApiError404 = (m = "Resource not found") =>
	applyDecorators(
		ApiExtraModels(ErrorEnvelopeDto),
		ApiNotFoundResponse({ schema: err(404, m, "Not Found") }),
	);

export const ApiError409 = (m = "Resource already exists") =>
	applyDecorators(
		ApiExtraModels(ErrorEnvelopeDto),
		ApiConflictResponse({ schema: err(409, m, "Conflict") }),
	);

export const ApiError429 = (m = "Too many requests") =>
	applyDecorators(
		ApiExtraModels(ErrorEnvelopeDto),
		ApiTooManyRequestsResponse({ schema: err(429, m, "Too Many Requests") }),
	);

export const ApiError500 = (m = "Internal server error") =>
	applyDecorators(
		ApiExtraModels(ErrorEnvelopeDto),
		ApiInternalServerErrorResponse({
			schema: err(500, m, "Internal Server Error"),
		}),
	);
