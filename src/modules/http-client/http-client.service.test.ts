// /* eslint-disable @typescript-eslint/no-require-imports */
// /* eslint-disable @typescript-eslint/no-unsafe-call */
// /* eslint-disable @typescript-eslint/no-unsafe-member-access */
// /* eslint-disable @typescript-eslint/no-unsafe-assignment */

// import { Injectable } from '@nestjs/common';
// import axios, { AxiosRequestConfig } from 'axios';
// import * as fs from 'fs';
// import * as forge from 'node-forge';
// import { sslConfig } from 'src/configs/ssl/ssl.config';

// @Injectable()
// export class HttpClientServiceTest {
//   private readonly client: any;
//   private readonly privateKey: any;

//   constructor() {
//     const { p12Path, p12Password } = sslConfig();
//     console.log('p12Path', p12Path);
//     console.log('p12Password', p12Password);

//     // Read the .p12 file
//     const p12Data = fs.readFileSync(p12Path);

//     // Parse the PKCS#12 file using node-forge
//     const p12Asn1 = forge.asn1.fromDer(p12Data.toString('binary'));
//     const p12 = forge.pkcs12.pkcs12FromAsn1(p12Asn1, false, p12Password);

//     console.log('p12', p12);

//     // Extract the private key and certificate
//     const keyBags = p12.getBags({
//       bagType: forge.pki.oids.pkcs8ShroudedKeyBag,
//     });

//     console.log('keyBags', keyBags);

//     console.log(
//       'keyBags[forge.pki.oids.pkcs8ShroudedKeyBag]',
//       cod,
//     );

//     console.log(
//       'keyBags[forge.pki.oids.pkcs8ShroudedKeyBag][0]',
//       keyBags[forge.pki.oids.pkcs8ShroudedKeyBag]?.[0],
//     );

//     const certBags = p12.getBags({
//       bagType: forge.pki.oids.x509Certificate,
//     });

//     console.log('certBags', certBags);

//     const key = keyBags[forge.pki.oids.pkcs8ShroudedKeyBag]?.[0]?.key;

//     // Try to find certificate in different bag types
//     let cert = certBags[forge.pki.oids.x509Certificate]?.[0]?.cert;
//     if (!cert) {
//       // Get all bags to find certificate
//       const allBags = p12.getBags();
//       for (const [bagType, bags] of Object.entries(allBags)) {
//         if (bags.length > 0 && bags[0].cert) {
//           cert = bags[0].cert;
//           console.log(`Found certificate in bag type: ${bagType}`);
//           break;
//         }
//       }
//     }

//     console.log('key', key);
//     console.log('cert', cert);

//     if (!key || !cert) {
//       throw new Error('Failed to extract key or certificate from .p12 file');
//     }

//     // Store private key for signing
//     this.privateKey = key;

//     // Convert to PEM format for use with https.Agent
//     const privateKeyPem = forge.pki.privateKeyToPem(key);
//     const certPem = forge.pki.certificateToPem(cert);

//     // Configure axios with mTLS options
//     this.client = axios.create({
//       httpsAgent: new (require('https').Agent)({
//         key: privateKeyPem,
//         cert: certPem,
//         passphrase: p12Password,
//         rejectUnauthorized: true, // Ensure server certificate is valid
//       }),
//       baseURL: 'https://target-server.com/api', // Replace with target server URL
//       headers: {
//         'Content-Type': 'application/json',
//       },
//     });
//   }

//   async sendRequest(endpoint: string, data: any = {}): Promise<any> {
//     try {
//       const config: AxiosRequestConfig = {
//         method: 'post', // or 'get', 'put', etc.
//         url: endpoint,
//         data: data,
//       };
//       const response = await this.client(config);
//       return response.data;
//     } catch (error) {
//       throw new Error(`HTTP request failed: ${error.message}`);
//     }
//   }

//   /**
//    * Tạo chữ ký PKCS#1 từ dữ liệu sử dụng khóa riêng
//    * @param data Dữ liệu cần ký
//    * @returns Chữ ký PKCS#1 dạng base64
//    */
//   createPKCS1Signature(data: string): string {
//     if (!this.privateKey) {
//       throw new Error('Private key not available');
//     }

//     // Tạo hash SHA-256 của dữ liệu
//     const md = forge.md.sha256.create();
//     md.update(data, 'utf8');
//     const hash = md.digest();

//     // Ký hash bằng khóa riêng (PKCS#1 v1.5)
//     const signature = this.privateKey.sign(md);

//     // Chuyển đổi sang base64
//     return forge.util.encode64(signature);
//   }

//   /**
//    * Tạo Ssl2 header theo yêu cầu: BASE64(username:password:signature:timestamp:pkcs1Signature)
//    * @param username Tên đăng nhập
//    * @param password Mật khẩu
//    * @param signature Chữ ký nhận từ đăng ký tích hợp
//    * @returns Ssl2 header dạng base64
//    */
//   createSsl2Header(
//     username: string,
//     password: string,
//     signature: string,
//   ): string {
//     const timestamp = Date.now().toString(); // Epoch time in milliseconds

//     // Tạo dữ liệu để ký: username:password:signature:timestamp
//     const dataToSign = `${username}:${password}:${signature}:${timestamp}`;

//     // Tạo chữ ký PKCS#1
//     const pkcs1Signature = this.createPKCS1Signature(dataToSign);

//     // Tạo Ssl2: BASE64(username:password:signature:timestamp:pkcs1Signature)
//     const ssl2Data = `${username}:${password}:${signature}:${timestamp}:${pkcs1Signature}`;

//     return forge.util.encode64(ssl2Data);
//   }
// }

//////

// private readonly client: any;

// constructor() {
//   const { p12Path, p12Password } = sslConfig();
//   console.log('p12Path', p12Path);
//   console.log('p12Password', p12Password);

//   // Read the .p12 file
//   const p12Data = fs.readFileSync(p12Path);

//   // Parse the PKCS#12 file using node-forge
//   const p12Asn1 = forge.asn1.fromDer(p12Data.toString('binary'));
//   const p12 = forge.pkcs12.pkcs12FromAsn1(p12Asn1, false, p12Password);

//   console.log('p12', p12);

//   // Extract the private key and certificate
//   const keyBags = p12.getBags({
//     bagType: forge.pki.oids.pkcs8ShroudedKeyBag,
//   });

//   const certBags = p12.getBags({
//     bagType: forge.pki.oids.x509Certificate,
//   });

//   const key = keyBags[forge.pki.oids.pkcs8ShroudedKeyBag]?.[0]?.key;
//   const cert = certBags[forge.pki.oids.x509Certificate]?.[0]?.cert;

//   console.log('key', key);
//   console.log('cert', cert);

//   if (!key || !cert) {
//     throw new Error('Failed to extract key or certificate from .p12 file');
//   }

//   // Convert to PEM format for use with https.Agent
//   const privateKeyPem = forge.pki.privateKeyToPem(key);
//   const certPem = forge.pki.certificateToPem(cert);

//   // Configure axios with mTLS options
//   this.client = axios.create({
//     httpsAgent: new (require('https').Agent)({
//       key: privateKeyPem,
//       cert: certPem,
//       passphrase: p12Password,
//       rejectUnauthorized: true, // Ensure server certificate is valid
//     }),
//     baseURL: 'https://target-server.com/api', // Replace with target server URL
//     headers: {
//       'Content-Type': 'application/json',
//     },
//   });
// }

// async sendRequest(endpoint: string, data: any = {}): Promise<any> {
//   try {
//     const config: AxiosRequestConfig = {
//       method: 'post', // or 'get', 'put', etc.
//       url: endpoint,
//       data: data,
//     };
//     const response = await this.client(config);
//     return response.data;
//   } catch (error) {
//     throw new Error(`HTTP request failed: ${error.message}`);
//   }
// }
