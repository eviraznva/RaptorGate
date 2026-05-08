import { Inject, Injectable } from '@nestjs/common';
import {
  CONFIG_SNAPSHOT_PUSH_SERVICE_TOKEN,
  type FactoryResetCommand,
  type FactoryResetResult,
  type IConfigSnapshotPushService,
} from '../ports/config-snapshot-push-service.interface.js';

@Injectable()
export class FactoryResetUseCase {
  constructor(
    @Inject(CONFIG_SNAPSHOT_PUSH_SERVICE_TOKEN)
    private readonly configSnapshotPushService: IConfigSnapshotPushService,
  ) {}

  execute(command: FactoryResetCommand): Promise<FactoryResetResult> {
    return this.configSnapshotPushService.factoryReset(command);
  }
}
