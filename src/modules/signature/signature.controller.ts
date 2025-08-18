import { Controller, Get } from '@nestjs/common';
import { SignatureService } from './signature.service';

@Controller('signature')
export class SignatureController {
  constructor(private signatureService: SignatureService) {}

  @Get('calculate-pkcs1-signature')
  getSignature() {
    const pkcs1Signature = this.signatureService.calculatePKCS1Signature();

    return {
      pkcs1Signature,
    };
  }

  @Get('calculate-ssl2')
  getSSL2() {
    const ssl2 = this.signatureService.calculateSSL2();

    return {
      ssl2,
    };
  }
}
