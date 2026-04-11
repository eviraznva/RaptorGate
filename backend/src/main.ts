import { existsSync, readFileSync, unlinkSync } from 'node:fs';
import { join } from 'node:path';
import { cwd } from 'node:process';
import { BadRequestException, Logger, ValidationPipe } from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import { NestFactory } from '@nestjs/core';
import { type MicroserviceOptions, Transport } from '@nestjs/microservices';
import type { NestExpressApplication } from '@nestjs/platform-express';
import { DocumentBuilder, SwaggerModule } from '@nestjs/swagger';
import { apiReference } from '@scalar/nestjs-api-reference';
import cookieParser from 'cookie-parser';
import { AppModule } from './app.module.js';
import type { Env } from './shared/config/env.validation.js';

async function bootstrap() {
  const logger = new Logger('Bootstrap');
  const certsDir = join(cwd(), 'devCerts');

  const httpsOptions = {
    key: readFileSync(join(certsDir, 'key.pem')),
    cert: readFileSync(join(certsDir, 'cert.pem')),
  };

  const app = await NestFactory.create<NestExpressApplication>(AppModule, {
    httpsOptions,
  });

  app.set('query parser', 'extended');

  const configService = app.get(ConfigService<Env, true>);
  const corsOrigins = configService.get('CORS_ORIGIN', { infer: true });
  const httpPort = configService.get('PORT', { infer: true });
  const cookieSecret = configService.get('COOKIE_SECRET', { infer: true });
  const grpcSocketPath = configService.get('GRPC_SOCKET_PATH', { infer: true });
  const protoRoot = join(process.cwd(), '..', 'proto');

  app.use(cookieParser(cookieSecret));

  app.enableCors({
    origin: corsOrigins,
    credentials: true,
  });

  const server = app.getHttpAdapter().getInstance();
  server.set('trust proxy', 1);

  const absoluteSocketPath = join(process.cwd(), grpcSocketPath);
  if (existsSync(absoluteSocketPath)) {
    logger.log('Cleaning up stale socket file...');

    try {
      unlinkSync(absoluteSocketPath);
      logger.log(`Socket cleaned: ${absoluteSocketPath}`);
    } catch (err) {
      const error = err as Error;

      logger.error(
        `Could not remove socket file: ${error.message}`,
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
    'services',
    'event_service.proto',
  );

  app.connectMicroservice<MicroserviceOptions>({
    transport: Transport.GRPC,
    options: {
      package: 'raptorgate.services',
      protoPath: join(protoRoot, 'services', 'event_service.proto'),
      loader: {
        includeDirs: [protoRoot],
      },
      url: `unix://${absoluteSocketPath}`,
    },
  });

  app.useGlobalPipes(
    new ValidationPipe({
      whitelist: true,
      forbidNonWhitelisted: true,
      transform: true,
      exceptionFactory: (errors) => {
        const first = Object.values(errors[0]?.constraints ?? {})[0];
        return new BadRequestException(first ?? 'Validation failed');
      },
    }),
  );

  const config = new DocumentBuilder()
    .setTitle('RaptorGateApi')
    .addBearerAuth(
      { type: 'http', scheme: 'bearer', bearerFormat: 'JWT' },
      'bearer',
    )
    .addSecurityRequirements('bearer')
    .setDescription('The RaptorGateApi API')
    .setVersion('1.0')
    .addTag('RaptorGateApi')
    .build();

  const document = SwaggerModule.createDocument(app, config);

  SwaggerModule.setup('api', app, document);

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
  logger.log(`Proto: ${protoPath}`);

  await app.listen(httpPort);

  logger.log(`HTTP server listening on https://localhost:${httpPort}`);
  logger.log(`API: https://localhost:${httpPort}/api`);
  logger.log(`Docs: https://localhost:${httpPort}/reference`);
}

bootstrap();
