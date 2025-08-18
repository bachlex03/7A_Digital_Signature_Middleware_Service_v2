import { Module } from '@nestjs/common';
import { HttpClientService } from './http-client.service';

@Module({
  imports: [],
  providers: [HttpClientService],
  exports: [HttpClientService],
})
export class HttpClientModule {}
