import { Module } from '@nestjs/common';
import { HttpClientService } from './http-client.service';
import { SignatureModule } from '../signature/signature.module';

@Module({
  imports: [SignatureModule],
  providers: [HttpClientService],
  exports: [HttpClientService],
})
export class HttpClientModule {}
