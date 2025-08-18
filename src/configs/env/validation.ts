/* eslint-disable @typescript-eslint/no-unsafe-call */
/* eslint-disable @typescript-eslint/no-unsafe-member-access */
/* eslint-disable @typescript-eslint/no-unsafe-assignment */

import * as Joi from 'joi';

export const envValidationSchema = Joi.object({
  NODE_ENV: Joi.string()
    .valid('development', 'production', 'test', 'provision')
    .required(),
  PORT: Joi.number().required(),

  // Digital Signature Service Configuration
  DIGITAL_SIGNATURE_URL: Joi.string().uri().required(),
  DIGITAL_SIGNATURE_RELYING_PARTY: Joi.string().required(),
  DIGITAL_SIGNATURE_RELYING_PARTY_USER: Joi.string().required(),
  DIGITAL_SIGNATURE_RELYING_PARTY_PASSWORD: Joi.string().required(),
  DIGITAL_SIGNATURE_RELYING_PARTY_SIGNATURE: Joi.string().required(),
  DIGITAL_SIGNATURE_RELYING_PARTY_KEYSTORE: Joi.string().required(),
  DIGITAL_SIGNATURE_RELYING_PARTY_KEYSTORE_PASSWORD: Joi.string().required(),
});
