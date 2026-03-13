import { DocumentBuilder, SwaggerModule } from '@nestjs/swagger';
import { apiReference } from '@scalar/nestjs-api-reference';
import { ValidationPipe } from '@nestjs/common';
import { NestFactory } from '@nestjs/core';
import { AppModule } from './app.module';

async function bootstrap() {
  const app = await NestFactory.create(AppModule);

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
  await app.listen(process.env.PORT ?? 3000);
}
bootstrap();
