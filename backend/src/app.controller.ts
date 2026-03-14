import { Controller, Get } from '@nestjs/common';
import { ApiTags } from '@nestjs/swagger';
import { IsPublic } from './infrastructure/decorators/public.decorator';

@ApiTags('Health Check')
@Controller('health')
export class AppController {
  constructor() {}

  @IsPublic()
  @Get()
  getHello(): string {
    return 'Hello World';
  }
}
