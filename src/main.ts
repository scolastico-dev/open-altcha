import { NestFactory } from '@nestjs/core';
import { AppModule } from './app.module';
import { ValidationPipe } from '@nestjs/common';
import { DocumentBuilder, SwaggerModule } from '@nestjs/swagger';
import { BaseConfigService, DomainConfigService } from './config';
import packageJson from '../package.json';
import { Request, Response, NextFunction } from 'express';

async function bootstrap(): Promise<void> {
  const config = new BaseConfigService();
  const logLevel = ['error', 'warn', 'log', 'debug', 'verbose'];
  const logIndex = logLevel.indexOf(config.logLevel);
  const logger = logLevel.slice(0, logIndex + 1) as Array<
    'error' | 'warn' | 'log' | 'verbose' | 'debug'
  >;

  const app = await NestFactory.create(AppModule, { logger });
  app.enableShutdownHooks();

  // Custom CORS middleware
  const domainConfigService = new DomainConfigService();
  app.use((req: Request, res: Response, next: NextFunction) => {
    // Check if the route is one of the APIs that need CORS allowed based on domain
    if (!req.path.startsWith('/captcha/') && !req.path.startsWith('/espeak/')) {
      return next();
    }

    const origin = req.headers.origin;
    if (!origin) {
      return next();
    }

    let allowedOrigin = false;

    // Check if localhost is allowed and the origin is localhost
    if (
      config.allowLocalhost &&
      (origin.startsWith('http://localhost') ||
        origin.startsWith('https://localhost') ||
        origin.startsWith('http://127.0.0.1') ||
        origin.startsWith('https://127.0.0.1'))
    ) {
      const domainParam = req.query.domain as string | undefined;
      if (!domainParam) {
        // If it's from localhost, it is expected that the domain is in the query parameters, if its not fail with a 400
        if (req.method === 'OPTIONS') {
          return res
            .status(400)
            .send(
              'Bad Request: domain query parameter is required for localhost',
            );
        }
        res.status(400).json({
          statusCode: 400,
          message:
            'Bad Request: domain query parameter is required for localhost',
        });
        return;
      }
      allowedOrigin = true;
    } else {
      // Find domain config by origin
      const domainConfig = domainConfigService.findByOrigin(origin);
      if (domainConfig) {
        allowedOrigin = true;
      }
    }

    if (allowedOrigin) {
      res.header('Access-Control-Allow-Origin', origin);
      res.header(
        'Access-Control-Allow-Methods',
        'GET,HEAD,PUT,PATCH,POST,DELETE,OPTIONS',
      );
      res.header(
        'Access-Control-Allow-Headers',
        'Content-Type, Accept, Authorization, x-altcha-spam-filter',
      );
      res.header('Access-Control-Allow-Credentials', 'true');
    }

    if (req.method === 'OPTIONS') {
      return res.status(204).end();
    }

    next();
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
