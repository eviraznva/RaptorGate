import { MicroserviceOptions, Transport } from '@nestjs/microservices';
import { DocumentBuilder, SwaggerModule } from '@nestjs/swagger';
import { existsSync, readFileSync, unlinkSync } from 'node:fs';
import { apiReference } from '@scalar/nestjs-api-reference';
import { Logger, ValidationPipe } from '@nestjs/common';
import { Env } from './shared/config/env.validation';
import { ConfigService } from '@nestjs/config';
import { NestFactory } from '@nestjs/core';
import cookieParser from 'cookie-parser';
import { AppModule } from './app.module';
import { cwd } from 'node:process';
import { join } from 'node:path';

async function bootstrap() {
  const logger = new Logger('Bootstrap');

  const httpsOptions = {
    key: readFileSync('/home/szymon/RaptorGate/backend/devCerts/key.pem'),
    cert: readFileSync('/home/szymon/RaptorGate/backend/devCerts/cert.pem'),
  };

  const app = await NestFactory.create(AppModule, {
    httpsOptions,
  });

  const configService = app.get(ConfigService<Env, true>);
  const httpPort = configService.get('PORT', { infer: true });
  const cookieSecret = configService.get('COOKIE_SECRET', { infer: true });
  const grpcSocketPath = configService.get('GRPC_SOCKET_PATH', { infer: true });

  // 🔐 COOKIE PARSER
  app.use(cookieParser(cookieSecret));

  // 🔥🔥🔥 KLUCZOWE DLA FRONTENDU
  app.enableCors({
    origin: [
      'http://localhost:5173', // Vite
      'http://localhost:3000', // docs
    ],
    credentials: true, // 🔥 MUSI BYĆ
  });

  // 🔥 DEV FIX – trust proxy (ważne przy cookies + https)
  const server = app.getHttpAdapter().getInstance();
  server.set('trust proxy', 1);

  // 🔧 SOCKET CLEANUP
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
      url: grpcUrl,
    },
  });

  // 🔐 VALIDATION
  app.useGlobalPipes(
    new ValidationPipe({
      whitelist: true,
      forbidNonWhitelisted: true,
      transform: true,
    }),
  );

  // 📄 SWAGGER
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
      layout: 'modern',
      defaultHttpClient: {
        targetKey: 'js',
        clientKey: 'fetch',
      },
      authentication: {
        preferredSecurityScheme: 'bearer',
        securitySchemes: {
          bearer: {
            token: process.env.DOCS_BEARER_TOKEN ?? '',
          },
        },
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