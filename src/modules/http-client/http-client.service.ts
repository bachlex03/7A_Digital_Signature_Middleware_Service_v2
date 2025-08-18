/* eslint-disable @typescript-eslint/no-require-imports */
/* eslint-disable @typescript-eslint/no-unsafe-call */
/* eslint-disable @typescript-eslint/no-unsafe-member-access */
/* eslint-disable @typescript-eslint/no-unsafe-assignment */

import { Injectable } from '@nestjs/common';
import axios, { AxiosRequestConfig } from 'axios';
import * as fs from 'fs';
import * as forge from 'node-forge';

@Injectable()
export class HttpClientService {
  private readonly client: any;

  constructor() {
    const p12Path = 'path/to/MPKI_BVQY7A_QK7.p12'; // Replace with actual path
    const p12Password = 'your_p12_password'; // Replace with the password for the .p12 file

    // Read the .p12 file
    const p12Data = fs.readFileSync(p12Path);

    // Parse the PKCS#12 file using node-forge
    const p12Asn1 = forge.asn1.fromDer(p12Data.toString('binary'));
    const p12 = forge.pkcs12.pkcs12FromAsn1(p12Asn1, false, p12Password);

    // Extract the private key and certificate
    const keyBags = p12.getBags({
      bagType: forge.pki.oids.pkcs8ShroudedKeyBag,
    });
    const certBags = p12.getBags({ bagType: forge.pki.oids.x509Certificate });

    const key = keyBags[forge.pki.oids.pkcs8ShroudedKeyBag]?.[0]?.key;
    const cert = certBags[forge.pki.oids.x509Certificate]?.[0]?.cert;

    if (!key || !cert) {
      throw new Error('Failed to extract key or certificate from .p12 file');
    }

    // Convert to PEM format for use with https.Agent
    const privateKeyPem = forge.pki.privateKeyToPem(key);
    const certPem = forge.pki.certificateToPem(cert);

    // Configure axios with mTLS options
    this.client = axios.create({
      httpsAgent: new (require('https').Agent)({
        key: privateKeyPem,
        cert: certPem,
        passphrase: p12Password,
        rejectUnauthorized: true, // Ensure server certificate is valid
      }),
      baseURL: 'https://target-server.com/api', // Replace with target server URL
      headers: {
        'Content-Type': 'application/json',
      },
    });
  }

  async sendRequest(endpoint: string, data: any = {}): Promise<any> {
    try {
      const config: AxiosRequestConfig = {
        method: 'post', // or 'get', 'put', etc.
        url: endpoint,
        data: data,
      };
      const response = await this.client(config);
      return response.data;
    } catch (error) {
      throw new Error(`HTTP request failed: ${error.message}`);
    }
  }
}
