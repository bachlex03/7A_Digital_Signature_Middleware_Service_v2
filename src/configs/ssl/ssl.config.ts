import * as path from 'path';

export const sslConfig = () => ({
  p12Path: path.join(
    __dirname,
    process.env.DIGITAL_SIGNATURE_RELYING_PARTY_KEYSTORE || '',
  ),
  p12Password:
    process.env.DIGITAL_SIGNATURE_RELYING_PARTY_KEYSTORE_PASSWORD || '',
});
