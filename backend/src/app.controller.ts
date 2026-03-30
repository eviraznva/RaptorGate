import { IsPublic } from './infrastructure/decorators/public.decorator.js';
import {
  ApiError429,
  ApiError500,
} from './presentation/decorators/api-error-response.decorator.js';
import { Controller, Get } from '@nestjs/common';
import { ApiTags } from '@nestjs/swagger';

@ApiTags('Health Check')
@Controller('health')
export class AppController {
  constructor() {}

  @IsPublic()
  @Get()
  @ApiError429('Too many requests')
  @ApiError500()
  getHello(): string {
    return 'Hello World!';
  }
}
