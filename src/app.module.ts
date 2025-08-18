/* eslint-disable @typescript-eslint/no-unsafe-call */
/* eslint-disable @typescript-eslint/no-unsafe-member-access */
/* eslint-disable @typescript-eslint/no-unsafe-assignment */

import { Module } from '@nestjs/common';
import { ConfigModule } from '@nestjs/config';

import { AppController } from './app.controller';
import { AppService } from './app.service';
import { configuration, envValidationSchema } from './configs/env';
import { HttpClientModule } from './modules/http-client/http-client.module';

@Module({
  imports: [
    ConfigModule.forRoot({
      envFilePath: `${process.cwd()}/.env.${process.env.NODE_ENV?.trim()}`,
      load: [configuration],
      isGlobal: true,
      validationSchema: envValidationSchema,
    }),
    HttpClientModule,
  ],
  controllers: [AppController],
  providers: [AppService],
})
export class AppModule {}
