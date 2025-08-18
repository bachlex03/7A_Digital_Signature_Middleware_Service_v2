import { HttpAdapterHost, NestFactory } from '@nestjs/core';
import { AppModule } from './app.module';
import { Logger } from '@nestjs/common';
import { GlobalExceptionFilter, HttpExceptionFilter } from './common/filters';
import addSwaggerExtension from './common/extensions/swagger';

async function bootstrap() {
  const app = await NestFactory.create(AppModule);
  const httpAdapter = app.get(HttpAdapterHost);
  const logger = new Logger('Bootstrap');

  // Swagger extension
  addSwaggerExtension(app);

  // Global filters
  app.useGlobalFilters(
    new GlobalExceptionFilter(httpAdapter),
    new HttpExceptionFilter(httpAdapter),
  );

  await app.listen(process.env.PORT ?? 3000);

  logger.debug(`🚀 This application is running on: ${await app.getUrl()}`);
  logger.debug(`📚 Swagger documentation: ${await app.getUrl()}/api-docs`);
  logger.debug(`🔧 Environment: ${process.env.NODE_ENV}`);
}

bootstrap().catch((error) => {
  console.error('Failed to start application:', error);
  process.exit(1);
});
