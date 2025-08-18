/* eslint-disable @typescript-eslint/no-unsafe-argument */
/* eslint-disable @typescript-eslint/no-require-imports */
/* eslint-disable @typescript-eslint/no-unsafe-call */
/* eslint-disable @typescript-eslint/no-unsafe-member-access */
/* eslint-disable @typescript-eslint/no-unsafe-assignment */

import * as fs from 'fs';
import * as forge from 'node-forge';
import { sslConfig } from 'src/configs/ssl/ssl.config';

export const getPKCS1Signature = (
  dataToSign: string,
  relyingPartyKeyStore: string,
  relyingPartyKeyStorePassword: string,
): string => {
  const { p12Path } = sslConfig();

  // Read and parse the .p12 file
  const p12Data = fs.readFileSync(p12Path);
  const p12Asn1 = forge.asn1.fromDer(p12Data.toString('binary'));
  const p12 = forge.pkcs12.pkcs12FromAsn1(
    p12Asn1,
    false,
    relyingPartyKeyStorePassword,
  );

  // Extract the private key and certificate
  const keyBags = p12.getBags({
    bagType: forge.pki.oids.pkcs8ShroudedKeyBag,
  });

  //   const certBags = p12.getBags({
  //     bagType: forge.pki.oids.x509Certificate,
  //   });

  const privateKey = keyBags[forge.pki.oids.pkcs8ShroudedKeyBag]?.[0]?.key;
  //   const cert = certBags[forge.pki.oids.x509Certificate]?.[0]?.cert;

  if (!privateKey) {
    throw new Error('Private key not found in .p12 file');
  }

  // Convert data to sign to UTF-8 bytes
  const md = forge.md.sha1.create();
  md.update(dataToSign, 'utf8');

  const signature = (privateKey as any).sign(md);

  const pkcs1Signature = forge.util.encode64(signature);

  return pkcs1Signature;
};
