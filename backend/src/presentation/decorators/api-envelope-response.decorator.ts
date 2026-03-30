import {
  ApiCreatedResponse,
  ApiExtraModels,
  ApiNoContentResponse,
  ApiOkResponse,
  getSchemaPath,
} from '@nestjs/swagger';
import { SuccessEnvelopeDto } from '../dtos/api-envelope.dto.js';
import { applyDecorators, Type } from '@nestjs/common';

export const ApiOkEnvelope = <TModel extends Type<unknown>>(
  model: TModel,
  message = 'Success',
) =>
  applyDecorators(
    ApiExtraModels(SuccessEnvelopeDto, model),
    ApiOkResponse({
      schema: {
        allOf: [
          { $ref: getSchemaPath(SuccessEnvelopeDto) },
          {
            properties: {
              statusCode: { example: 200 },
              message: { example: message },
              data: { $ref: getSchemaPath(model) },
            },
          },
        ],
      },
    }),
  );

export const ApiCreatedEnvelope = <TModel extends Type<unknown>>(
  model: TModel,
  message = 'Resource created',
) =>
  applyDecorators(
    ApiExtraModels(SuccessEnvelopeDto, model),
    ApiCreatedResponse({
      schema: {
        allOf: [
          { $ref: getSchemaPath(SuccessEnvelopeDto) },
          {
            properties: {
              statusCode: { example: 201 },
              message: { example: message },
              data: { $ref: getSchemaPath(model) },
            },
          },
        ],
      },
    }),
  );

export const ApiNoContentEnvelope = (description = 'No content') =>
  applyDecorators(ApiNoContentResponse({ description }));

// export const ApiBadRequestEnvelope = (example = 'Invalid request') =>
//   applyDecorators(
//     ApiBadRequestResponse({
//       type: ErrorEnvelopeDto,
//       description: example,
//     }),
//   );
