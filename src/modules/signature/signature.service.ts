/* eslint-disable @typescript-eslint/no-require-imports */
/* eslint-disable @typescript-eslint/no-unsafe-call */
/* eslint-disable @typescript-eslint/no-unsafe-member-access */
/* eslint-disable @typescript-eslint/no-unsafe-assignment */

import { Injectable } from '@nestjs/common';
import { getPKCS1Signature } from 'src/utils/get-PKCS1-signature';
import { getSSL2 } from 'src/utils/get-SSL2';

@Injectable()
export class SignatureService {
  constructor() {}

  calculatePKCS1Signature(): string {
    const relyingPartyUser =
      process.env.DIGITAL_SIGNATURE_RELYING_PARTY_USER || '';
    const relyingPartyPassword =
      process.env.DIGITAL_SIGNATURE_RELYING_PARTY_PASSWORD || '';
    const relyingPartySignature =
      process.env.DIGITAL_SIGNATURE_RELYING_PARTY_SIGNATURE || '';
    const relyingPartyKeyStore =
      process.env.DIGITAL_SIGNATURE_RELYING_PARTY_KEYSTORE || '';
    const relyingPartyKeyStorePassword =
      process.env.DIGITAL_SIGNATURE_RELYING_PARTY_KEYSTORE_PASSWORD || '';

    console.log('relyingPartyUser', relyingPartyUser);
    console.log('relyingPartyPassword', relyingPartyPassword);
    console.log('relyingPartySignature', relyingPartySignature);
    console.log('relyingPartyKeyStore', relyingPartyKeyStore);
    console.log('relyingPartyKeyStorePassword', relyingPartyKeyStorePassword);

    const timestamp = (
      Date.now() - new Date(Date.UTC(1970, 0, 1, 0, 0, 0)).getTime()
    ).toString();

    const dataToSign = `${relyingPartyUser}${relyingPartyPassword}${relyingPartySignature}${timestamp}`;

    const pkcs1Signature = getPKCS1Signature(
      dataToSign,
      relyingPartyKeyStore,
      relyingPartyKeyStorePassword,
    );

    return pkcs1Signature;
  }

  calculateSSL2() {
    const relyingPartyUser =
      process.env.DIGITAL_SIGNATURE_RELYING_PARTY_USER || '';
    const relyingPartyPassword =
      process.env.DIGITAL_SIGNATURE_RELYING_PARTY_PASSWORD || '';
    const relyingPartySignature =
      process.env.DIGITAL_SIGNATURE_RELYING_PARTY_SIGNATURE || '';
    const relyingPartyKeyStore =
      process.env.DIGITAL_SIGNATURE_RELYING_PARTY_KEYSTORE || '';
    const relyingPartyKeyStorePassword =
      process.env.DIGITAL_SIGNATURE_RELYING_PARTY_KEYSTORE_PASSWORD || '';

    const ssl2 = getSSL2(
      relyingPartyUser,
      relyingPartyPassword,
      relyingPartySignature,
      relyingPartyKeyStore,
      relyingPartyKeyStorePassword,
    );

    return ssl2;
  }
}
