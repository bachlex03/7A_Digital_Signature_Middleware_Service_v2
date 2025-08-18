import { getPKCS1Signature } from './get-PKCS1-signature';

export const getSSL2 = (
  relyingPartyUser: string,
  relyingPartyPassword: string,
  relyingPartySignature: string,
  relyingPartyKeyStore: string,
  relyingPartyKeyStorePassword: string,
) => {
  const timestamp = (
    Date.now() - new Date(Date.UTC(1970, 0, 1, 0, 0, 0)).getTime()
  ).toString();

  const dataToSign = `${relyingPartyUser}${relyingPartyPassword}${relyingPartySignature}${timestamp}`;

  const pkcs1Signature = getPKCS1Signature(
    dataToSign,
    relyingPartyKeyStore,
    relyingPartyKeyStorePassword,
  );

  const ssl2 = `${relyingPartyUser}:${relyingPartyPassword}:${pkcs1Signature}:${timestamp}:${pkcs1Signature}`;

  return ssl2;
};
