/* eslint-disable @typescript-eslint/no-unsafe-call */
/* eslint-disable @typescript-eslint/no-unsafe-member-access */
/* eslint-disable @typescript-eslint/no-unsafe-assignment */

import { INestApplication } from '@nestjs/common';
import { DocumentBuilder, SwaggerModule } from '@nestjs/swagger';

const addSwaggerExtension = (app: INestApplication) => {
  const swaggerUrl = '/api-docs';

  const builder = new DocumentBuilder()
    .setTitle('Digital Signature Middleware Service')
    .setDescription('API for digital signature middleware service')
    .setVersion('1.0')
    .addBearerAuth()
    .build();

  const documentFactory = SwaggerModule.createDocument(app, builder);

  SwaggerModule.setup(swaggerUrl, app, documentFactory, {
    jsonDocumentUrl: 'api-docs/json',
  });
};

export default addSwaggerExtension;
