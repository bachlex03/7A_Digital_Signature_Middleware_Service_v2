import { HttpAdapterHost, NestFactory } from '@nestjs/core';
import { AppModule } from './app.module';
import { Logger } from '@nestjs/common';
import { GlobalExceptionFilter, HttpExceptionFilter } from './common/filters';

async function bootstrap() {
  const app = await NestFactory.create(AppModule);
  const httpAdapter = app.get(HttpAdapterHost);
  const logger = new Logger('Bootstrap');

  // Global filters
  app.useGlobalFilters(
    new GlobalExceptionFilter(httpAdapter),
    new HttpExceptionFilter(httpAdapter),
  );

  await app.listen(process.env.PORT ?? 3000);

  logger.debug(`🔧 Environment: ${process.env.NODE_ENV}`, 'Bootstrap');
  logger.debug(
    `🚀 This application is running on: ${await app.getUrl()}`,
    'Bootstrap',
  );

  logger.debug(
    `📚 Swagger documentation: ${await app.getUrl()}/api-docs`,
    'Bootstrap',
  );
}

bootstrap().catch((error) => {
  console.error('Failed to start application:', error);
  process.exit(1);
});
