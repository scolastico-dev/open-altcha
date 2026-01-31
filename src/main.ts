import { NestFactory } from '@nestjs/core';
import { AppModule } from './app.module';
import { ValidationPipe } from '@nestjs/common';
import { DocumentBuilder, SwaggerModule } from '@nestjs/swagger';
import { BaseConfigService } from './config';
import packageJson from '../package.json';

async function bootstrap(): Promise<void> {
  const app = await NestFactory.create(AppModule);
  app.enableShutdownHooks();

  // Get configuration
  const config = app.get(BaseConfigService);

  // Enable CORS for cross-origin requests
  app.enableCors({
    origin: true,
    credentials: true,
  });

  // Global validation pipe
  app.useGlobalPipes(
    new ValidationPipe({
      transform: true,
      whitelist: true,
      forbidNonWhitelisted: true,
    }),
  );

  // Setup Swagger documentation
  const swaggerConfig = new DocumentBuilder()
    .setTitle('ALTCHA Server')
    .setDescription(
      'A challenge-response system to protect your web applications from bots and automated abuse.',
    )
    .setVersion(packageJson.version)
    .build();

  const document = SwaggerModule.createDocument(app, swaggerConfig);
  SwaggerModule.setup('swagger', app, document, {
    jsonDocumentUrl: 'swagger.json',
  });

  const port = config.port;
  await app.listen(port);
}

bootstrap().catch((e) => {
  console.error('Failed to bootstrap the application', e);
  process.exit(1);
});
