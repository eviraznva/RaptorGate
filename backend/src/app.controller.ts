import { Controller, Get } from '@nestjs/common';
import { ApiTags } from '@nestjs/swagger';

@ApiTags('Health Check')
@Controller('health')
export class AppController {
  constructor() {}

  @Get()
  getHello(): string {
    return 'Hello World';
  }
}
