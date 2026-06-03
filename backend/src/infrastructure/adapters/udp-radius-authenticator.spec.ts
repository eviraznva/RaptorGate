import { UdpRadiusAuthenticator } from './udp-radius-authenticator.js';

describe('UdpRadiusAuthenticator', () => {
  it('tries ordered endpoints until one accepts', async () => {
    const attempted: string[] = [];
    const authenticator = new UdpRadiusAuthenticator(async (attempt) => {
      attempted.push(attempt.server.name);
      if (attempt.server.name === 'primary') {
        return { kind: 'timeout' };
      }
      return {
        kind: 'accept',
        groups: ['admins'],
        attributes: {
          userGroups: ['admins'],
          adminRole: null,
          accessDomain: null,
          panoramaAdminRole: null,
          panoramaAccessDomain: null,
          userDomain: null,
          rawDiagnostics: [],
        },
      };
    });

    const result = await authenticator.authenticate({
      username: 'alice',
      password: 'password',
      callingStationId: '198.51.100.10',
      profile: {
        authenticationProtocol: 'pap',
        timeoutMs: 10,
        retries: 0,
        nasIp: '192.0.2.1',
        nasIdentifier: 'raptorgate',
        calledStationId: null,
        servers: [
          {
            name: 'secondary',
            host: '192.0.2.11',
            port: 1812,
            secret: 'secondary-secret',
            priority: 2,
          },
          {
            name: 'primary',
            host: '192.0.2.10',
            port: 1812,
            secret: 'primary-secret',
            priority: 1,
          },
        ],
      },
    });

    expect(result).toMatchObject({
      kind: 'accept',
      groups: ['admins'],
      attemptedEndpoints: ['primary', 'secondary'],
    });
    expect(attempted).toEqual(['primary', 'secondary']);
  });
});
