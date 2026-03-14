import { Module } from '@nestjs/common';
import { RaptorGateController } from './raptorgate.controller';
@Module({
  controllers: [RaptorGateController],
})
export class GrpcModule {}
