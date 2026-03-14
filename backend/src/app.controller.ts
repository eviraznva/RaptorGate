import { IsPublic } from './infrastructure/decorators/public.decorator';
import { Controller, Get } from '@nestjs/common';
import { ApiTags } from '@nestjs/swagger';

@ApiTags('Health Check')
@Controller('health')
export class AppController {
  constructor() {}

  @IsPublic()
  @Get()
  getHello(): string {
    return 'Hello World!';
  }
}
