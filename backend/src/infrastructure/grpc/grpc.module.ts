import { RaptorGateController } from './raptorgate.controller.js';
import { Module } from '@nestjs/common';

@Module({
  imports: [],
  controllers: [RaptorGateController],
  providers: [],
})
export class GrpcModule {}
