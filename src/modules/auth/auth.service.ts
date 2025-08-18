import { Injectable, Logger, UnauthorizedException } from '@nestjs/common';
import { HttpService } from '@nestjs/axios';
import { ConfigService } from '@nestjs/config';
import { firstValueFrom } from 'rxjs';
import * as fs from 'fs';
import * as forge from 'node-forge';
import { LoginRequestDto } from './dto/login-request.dto';
import { LoginResponseDto } from './dto/login-response.dto';
import { sslConfig } from 'src/configs/ssl/ssl.config';

@Injectable()
export class AuthService {
  private readonly logger = new Logger(AuthService.name);
  private privateKey: any;
  private bearerToken: string | null = null;
  private refreshToken: string | null = null;
  private retryLoginCount = 0;
  private readonly maxRetries = 5;

  constructor(
    private readonly httpService: HttpService,
    private readonly configService: ConfigService,
  ) {
    this.initializePrivateKey();
  }

  private initializePrivateKey(): void {
    try {
      const { p12Path, p12Password } = sslConfig();

      if (!p12Path || !p12Password) {
        throw new Error('SSL configuration not found');
      }

      // Read and parse the .p12 file
      const p12Data = fs.readFileSync(p12Path);
      const p12Asn1 = forge.asn1.fromDer(p12Data.toString('binary'));
      const p12 = forge.pkcs12.pkcs12FromAsn1(p12Asn1, false, p12Password);

      // Extract the private key
      const keyBags = p12.getBags({
        bagType: forge.pki.oids.pkcs8ShroudedKeyBag,
      });

      const privateKey = keyBags[forge.pki.oids.pkcs8ShroudedKeyBag]?.[0]?.key;
      if (!privateKey) {
        throw new Error('Private key not found in .p12 file');
      }

      this.privateKey = privateKey;
      this.logger.log('Private key initialized successfully');
    } catch (error) {
      this.logger.error('Failed to initialize private key', error);
      throw error;
    }
  }

  /**
   * Main login method - equivalent to C# ServerSession.login()
   */
  async login(username: string, password: string): Promise<LoginResponseDto> {
    this.logger.log('____________auth/login____________');

    let authHeader: string;
    if (this.refreshToken) {
      authHeader = this.refreshToken;
    } else {
      this.retryLoginCount++;
      authHeader = this.generateAuthorizationHeader(username, password);
    }

    this.logger.log(`Login-retry: ${this.retryLoginCount}`);

    try {
      const loginRequest: LoginRequestDto = {
        rememberMeEnabled: true,
        relyingParty: process.env.DIGITAL_SIGNATURE_RELYING_PARTY || '',
        lang: 'en',
      };

      const response = await this.sendLoginRequest(loginRequest, authHeader);

      if (response.error === 3005 || response.error === 3006) {
        // Token expired or invalid
        this.refreshToken = null;
        if (this.retryLoginCount >= this.maxRetries) {
          this.retryLoginCount = 0;
          throw new UnauthorizedException(response.errorDescription);
        }
        return this.login(username, password); // Retry
      } else if (response.error !== 0) {
        throw new UnauthorizedException(response.errorDescription);
      }

      // Success - store tokens
      this.bearerToken = `Bearer ${response.accessToken}`;
      if (response.refreshToken) {
        this.refreshToken = `Bearer ${response.refreshToken}`;
      }

      this.logger.log(`Response code: ${response.error}`);
      this.logger.log(`Response Description: ${response.errorDescription}`);
      this.logger.log(`Response ID: ${response.responseID}`);
      this.logger.log(`AccessToken: ${response.accessToken}`);

      return response;
    } catch (error) {
      this.logger.error('Login failed', error);
      throw error;
    }
  }

  /**
   * Generate SSL2 authorization header - equivalent to C# Property.getAuthorization()
   */
  private generateAuthorizationHeader(
    username: string,
    password: string,
  ): string {
    const timestamp = Date.now().toString();
    const relyingPartyUser = this.configService.get<string>(
      'DIGITAL_SIGNATURE_RELYING_PARTY_USER',
    );
    const relyingPartyPassword = this.configService.get<string>(
      'DIGITAL_SIGNATURE_RELYING_PARTY_PASSWORD',
    );
    const relyingPartySignature = this.configService.get<string>(
      'DIGITAL_SIGNATURE_RELYING_PARTY_SIGNATURE',
    );

    if (!relyingPartyUser || !relyingPartyPassword || !relyingPartySignature) {
      throw new Error('Missing relying party configuration');
    }

    // Create data to sign: username:password:signature:timestamp
    const dataToSign = `${relyingPartyUser}${relyingPartyPassword}${relyingPartySignature}${timestamp}`;

    // Generate PKCS1 signature
    const pkcs1Signature = this.createPKCS1Signature(dataToSign);

    // Create SSL2 header: BASE64(username:password:signature:timestamp:pkcs1Signature)
    const ssl2Data = `${relyingPartyUser}:${relyingPartyPassword}:${relyingPartySignature}:${timestamp}:${pkcs1Signature}`;
    const ssl2Encoded = forge.util.encode64(ssl2Data);

    // Create Basic auth: BASE64(USERNAME:username:password)
    const basicData = `USERNAME:${username}:${password}`;
    const basicEncoded = forge.util.encode64(basicData);

    return `SSL2 ${ssl2Encoded}, Basic ${basicEncoded}`;
  }

  /**
   * Create PKCS1 signature using private key
   */
  private createPKCS1Signature(data: string): string {
    if (!this.privateKey) {
      throw new Error('Private key not available');
    }

    // Create SHA-256 hash of data
    const md = forge.md.sha256.create();
    md.update(data, 'utf8');

    // Sign hash with private key (PKCS#1 v1.5)
    const signature = (this.privateKey as any).sign(md);

    // Convert to base64
    return forge.util.encode64(signature);
  }

  /**
   * Send login request to auth/login endpoint
   */
  private async sendLoginRequest(
    loginRequest: LoginRequestDto,
    authHeader: string,
  ): Promise<LoginResponseDto> {
    const baseUrl = this.configService.get<string>('DIGITAL_SIGNATURE_URL');

    console.log('loginRequest', loginRequest);
    console.log('authHeader', authHeader);

    const url = `${baseUrl}/auth/login`;

    try {
      const response = await firstValueFrom(
        this.httpService.post<LoginResponseDto>(url, loginRequest, {
          headers: {
            Authorization: authHeader,
            'Content-Type': 'application/json',
          },
        }),
      );

      console.log('response.data', response.data);

      return response.data;
    } catch (error) {
      this.logger.error('HTTP request failed', error);
      throw new Error(`HTTP request failed: ${error.message}`);
    }
  }

  /**
   * Get current bearer token
   */
  getBearerToken(): string | null {
    return this.bearerToken;
  }

  /**
   * Check if user is authenticated
   */
  isAuthenticated(): boolean {
    return !!this.bearerToken;
  }

  /**
   * Logout and clear tokens
   */
  logout(): void {
    this.bearerToken = null;
    this.refreshToken = null;
    this.retryLoginCount = 0;
    this.logger.log('User logged out');
  }
}
