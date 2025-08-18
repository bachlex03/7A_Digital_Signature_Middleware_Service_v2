export const configuration = () => ({
  NODE_ENV: process.env.NODE_ENV,
  port: parseInt(process.env.PORT as string, 10),

  // Digital Signature Service Configuration
  digitalSignature: {
    url: process.env.DIGITAL_SIGNATURE_URL,
    relyingParty: process.env.DIGITAL_SIGNATURE_RELYING_PARTY,
    relyingPartyUser: process.env.DIGITAL_SIGNATURE_RELYING_PARTY_USER,
    relyingPartyPassword: process.env.DIGITAL_SIGNATURE_RELYING_PARTY_PASSWORD,
    relyingPartySignature:
      process.env.DIGITAL_SIGNATURE_RELYING_PARTY_SIGNATURE,
    relyingPartyKeystore: process.env.DIGITAL_SIGNATURE_RELYING_PARTY_KEYSTORE,
    relyingPartyKeystorePassword:
      process.env.DIGITAL_SIGNATURE_RELYING_PARTY_KEYSTORE_PASSWORD,
  },
});
