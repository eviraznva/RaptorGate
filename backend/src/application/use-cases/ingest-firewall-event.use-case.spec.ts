import { jest } from '@jest/globals';
import { Test, type TestingModule } from '@nestjs/testing';
import { FirewallEvent } from '../../domain/firewall-events/firewall-event.js';
import { FIREWALL_EVENT_SINK_TOKEN } from '../ports/firewall-event-sink.port.js';
import { IngestFirewallEventUseCase } from './ingest-firewall-event.use-case.js';

describe('IngestFirewallEventUseCase', () => {
  let useCase: IngestFirewallEventUseCase;

  const sink = {
    write: jest.fn(),
  };

  beforeEach(async () => {
    sink.write.mockReset();

    const module: TestingModule = await Test.createTestingModule({
      providers: [
        IngestFirewallEventUseCase,
        {
          provide: FIREWALL_EVENT_SINK_TOKEN,
          useValue: sink,
        },
      ],
    }).compile();

    useCase = module.get(IngestFirewallEventUseCase);
  });

  it('writes supported event to sink', async () => {
    const event: FirewallEvent = {
      timestamp: '2023-11-14T22:13:20.000Z',
      event_type: 'ips_signature_matched',
      source: 'IPS',
      decision: 'block',
      signature_id: 'ET-001',
    };

    await useCase.execute(event);

    expect(sink.write).toHaveBeenCalledWith(event);
  });

  it('skips null events', async () => {
    await useCase.execute(null);

    expect(sink.write).not.toHaveBeenCalled();
  });
});
