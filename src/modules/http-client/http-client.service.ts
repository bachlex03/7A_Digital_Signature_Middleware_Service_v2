/* eslint-disable @typescript-eslint/no-require-imports */
/* eslint-disable @typescript-eslint/no-unsafe-call */
/* eslint-disable @typescript-eslint/no-unsafe-member-access */
/* eslint-disable @typescript-eslint/no-unsafe-assignment */

import { Injectable } from '@nestjs/common';
import axios, { AxiosInstance } from 'axios';
import { SignatureService } from '../signature/signature.service';

@Injectable()
export class HttpClientService {
  private readonly client: AxiosInstance;

  constructor(private readonly signatureService: SignatureService) {
    this.client = axios.create({
      baseURL: process.env.DIGITAL_SIGNATURE_URL,
      headers: {
        'Content-Type': 'application/json',
      },
    });
  }

  async sendPostRequest(url: string, data: any): Promise<any> {
    const signature = this.signatureService.calculateSSL2();

    const config = {
      headers: {
        Authorization: `SSL2 ${signature}`,
      },
    };

    const response = await this.client.post(url, data, config);
    return response.data;
  }
}
