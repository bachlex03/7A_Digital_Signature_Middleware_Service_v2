import * as path from 'path';

export const sslConfig = () => ({
  digitalSignatureUrl: process.env.DIGITAL_SIGNATURE_URL || '',
  relyingParty: process.env.DIGITAL_SIGNATURE_RELYING_PARTY || '',
  relyingPartyUser: process.env.DIGITAL_SIGNATURE_RELYING_PARTY_USER || '',
  relyingPartyPassword:
    process.env.DIGITAL_SIGNATURE_RELYING_PARTY_PASSWORD || '',
  relyingPartySignature:
    process.env.DIGITAL_SIGNATURE_RELYING_PARTY_SIGNATURE || '',
  p12Name: process.env.DIGITAL_SIGNATURE_RELYING_PARTY_KEYSTORE || '',
  p12Path: path.join(
    __dirname,
    process.env.DIGITAL_SIGNATURE_RELYING_PARTY_KEYSTORE || '',
  ),
  p12Password:
    process.env.DIGITAL_SIGNATURE_RELYING_PARTY_KEYSTORE_PASSWORD || '',
});
