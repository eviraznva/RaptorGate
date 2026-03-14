import { MicroserviceOptions, Transport } from '@nestjs/microservices';
import { DocumentBuilder, SwaggerModule } from '@nestjs/swagger';
import { apiReference } from '@scalar/nestjs-api-reference';
import { Env } from './shared/config/env.validation';
import { existsSync, unlinkSync } from 'node:fs';
import { Logger, ValidationPipe } from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import { NestFactory } from '@nestjs/core';
import { AppModule } from './app.module';
import { join } from 'node:path';
import { cwd } from 'node:process';

async function bootstrap() {
  const logger = new Logger('Bootstrap');
  const app = await NestFactory.create(AppModule);

  const configService = app.get(ConfigService<Env, true>);
  const grpcSocketPath = configService.get('GRPC_SOCKET_PATH', { infer: true });
  const httpPort = configService.get('PORT', { infer: true });

  const absoluteSocketPath = join(process.cwd(), grpcSocketPath);
  if (existsSync(absoluteSocketPath)) {
    logger.log('Cleaning up stale socket file...');
    try {
      unlinkSync(absoluteSocketPath);
      logger.log(`Socket cleaned: ${absoluteSocketPath}`);
    } catch (err) {
      const error = err as Error;
      logger.error(
        `✗ Could not remove socket file: ${error.message}`,
        error.stack,
      );
      throw error;
    }
  }

  const grpcUrl = `unix://${absoluteSocketPath}`;
  const protoPath = join(
    process.cwd(),
    '..',
    'proto',
    'config',
    'config_service.proto',
  );

  app.connectMicroservice<MicroserviceOptions>({
    transport: Transport.GRPC,
    options: {
      package: ['raptorgate', 'raptorgate.config', 'raptorgate.events'],
      protoPath: join(cwd(), '..', 'proto', 'raptorgate.proto'),
      loader: { includeDirs: [join(cwd(), '..', 'proto')] },
      url: `unix://${absoluteSocketPath}`,
    },
  });

  app.useGlobalPipes(
    new ValidationPipe({
      whitelist: true,
      forbidNonWhitelisted: true,
      transform: true,
    }),
  );

  const config = new DocumentBuilder()
    .setTitle('RaptorGateApi')
    .setDescription('The RaptorGateApi API')
    .setVersion('1.0')
    .addTag('RaptorGateApi')
    .build();

  const documentFactory = () => SwaggerModule.createDocument(app, config);

  SwaggerModule.setup('api', app, documentFactory);

  const document = SwaggerModule.createDocument(app, config);
  app.use(
    '/reference',
    apiReference({
      theme: 'default',
      content: document,
      darkMode: true,
      hideClientButton: false,
      hideModels: false,
      hideDownloadButton: false,
      hideTestRequestButton: false,
      layout: 'modern',
      searchHotKey: 'k',
      defaultHttpClient: {
        targetKey: 'js',
        clientKey: 'fetch',
      },
      authentication: {
        preferredSecurityScheme: 'bearer',
        securitySchemes: {
          bearer: {
            token: '',
          },
        },
      },
      showSidebar: true,
      defaultOpenAllTags: true,
      hideSearch: false,
      favicon: '/favicon.ico',
      metaData: {
        title: 'RaptorGate API Documentation',
        description: 'Interactive API reference for RaptorGate',
      },
    }),
  );

  await app.startAllMicroservices();

  logger.log(`gRPC server listening on ${grpcUrl}`);
  logger.log(`Package: raptorgate.config`);
  logger.log(`Proto: ${protoPath}`);

  await app.listen(httpPort);

  logger.log(`HTTP server listening on http://localhost:${httpPort}`);
  logger.log(`API Documentation: http://localhost:${httpPort}/api`);
  logger.log(`API Reference: http://localhost:${httpPort}/reference`);
}
bootstrap();
