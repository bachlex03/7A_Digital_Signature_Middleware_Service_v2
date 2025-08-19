/* eslint-disable @typescript-eslint/no-unsafe-call */
/* eslint-disable @typescript-eslint/no-unsafe-assignment */
/* eslint-disable @typescript-eslint/no-unsafe-member-access */
import { Injectable, Logger, UnauthorizedException } from '@nestjs/common';
import { HttpService } from '@nestjs/axios';
import { ConfigService } from '@nestjs/config';
import { firstValueFrom } from 'rxjs';
import * as fs from 'fs';
import * as forge from 'node-forge';
import { LoginRequestDto } from './dto/login-request.dto';
import { LoginResponseDto } from './dto/login-response.dto';
import { CredentialListRequestDto } from './dto/credential-list-request.dto';
import { CredentialInfoRequestDto } from './dto/credential-info-request.dto';
import { CredentialAuthorizeRequestDto } from './dto/credential-authorize-request.dto';
import { sslConfig } from 'src/configs/ssl/ssl.config';
import MakeSignature from 'src/utils/make-signature';

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

    const { relyingParty } = sslConfig();

    let authHeader: string;
    if (this.refreshToken) {
      authHeader = this.refreshToken;
    } else {
      this.retryLoginCount++;
      authHeader = this.generateAuthorizationHeader(username, password);
    }

    console.log('authHeader', authHeader);

    this.logger.log(`Login-retry: ${this.retryLoginCount}`);

    try {
      const loginRequest: LoginRequestDto = {
        rememberMeEnabled: true,
        relyingParty: relyingParty,
        profile: 'rssp-119.432-v2.0',
        lang: 'VN',
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
    // const timestamp = Date.now().toString();
    const timestamp2 = (
      Date.now() - new Date(1970, 0, 1, 0, 0, 0, 0).getTime()
    ).toString();

    const {
      digitalSignatureUrl,
      relyingParty,
      relyingPartyUser,
      relyingPartyPassword,
      relyingPartySignature,
      p12Name,
      p12Path,
      p12Password,
    } = sslConfig();

    console.log('digitalSignatureUrl', digitalSignatureUrl);
    console.log('relyingParty', relyingParty);
    console.log('relyingPartyUser', relyingPartyUser);
    console.log('relyingPartyPassword', relyingPartyPassword);
    console.log('relyingPartySignature', relyingPartySignature);
    console.log('p12Name', p12Name);
    console.log('p12Path', p12Path);
    console.log('p12Password', p12Password);

    if (!relyingPartyUser || !relyingPartyPassword || !relyingPartySignature) {
      throw new Error('Missing relying party configuration');
    }

    // Create data to sign: username + password + signature + timestamp
    const dataToSign = `${relyingPartyUser}${relyingPartyPassword}${relyingPartySignature}${timestamp2}`;

    // Generate PKCS1 signature
    const pkcs1Signature = this.createPKCS1Signature(dataToSign);
    console.log('pkcs1Signature', pkcs1Signature);

    //test
    const pkcs1Signature2 = new MakeSignature(dataToSign, p12Path, p12Password);
    console.log('pkcs1Signature2', pkcs1Signature2.getSignature());

    // Create SSL2 header: BASE64(username:password:signature:timestamp:pkcs1Signature)
    const ssl2Data = `${relyingPartyUser}:${relyingPartyPassword}:${relyingPartySignature}:${timestamp2}:${pkcs1Signature2.getSignature()}`;
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
   * Get list of credentials - equivalent to C# ServerSession.listCertificates()
   */
  async getListCredentials(
    agreementUUID?: string,
    certificate?: string,
    certInfoEnabled: boolean = false,
    authInfoEnabled: boolean = false,
    searchConditions?: any,
  ): Promise<any> {
    this.logger.log('____________credentials/list____________');

    if (!this.bearerToken) {
      throw new UnauthorizedException('Not authenticated. Please login first.');
    }

    try {
      const credentialListRequest = {
        agreementUUID,
        certificates: certificate,
        certInfoEnabled,
        authInfoEnabled,
        searchConditions,
        lang: 'VN',
      };

      const response = await this.sendCredentialListRequest(
        credentialListRequest,
      );

      if (response.error === 3005 || response.error === 3006) {
        // Token expired or invalid - retry login and retry request
        this.logger.log('Token expired, attempting to relogin...');
        await this.login(
          process.env.DIGITAL_SIGNATURE_RELYING_PARTY_USER || '',
          process.env.DIGITAL_SIGNATURE_RELYING_PARTY_PASSWORD || '',
        );
        return this.getListCredentials(
          agreementUUID,
          certificate,
          certInfoEnabled,
          authInfoEnabled,
          searchConditions,
        );
      } else if (response.error !== 0) {
        throw new UnauthorizedException(response.errorDescription);
      }

      this.logger.log(`Error code: ${response.error}`);
      this.logger.log(`Error description: ${response.errorDescription}`);

      return response;
    } catch (error) {
      this.logger.error('Failed to get credentials list', error);
      throw error;
    }
  }

  /**
   * Send credentials list request to credentials/list endpoint
   */
  private async sendCredentialListRequest(
    credentialListRequest: any,
  ): Promise<any> {
    const baseUrl = this.configService.get<string>('DIGITAL_SIGNATURE_URL');
    const url = `${baseUrl}/credentials/list`;

    try {
      const response = await firstValueFrom(
        this.httpService.post(url, credentialListRequest, {
          headers: {
            Authorization: this.bearerToken,
            'Content-Type': 'application/json',
          },
        }),
      );

      return response.data;
    } catch (error) {
      this.logger.error('HTTP request failed for credentials list', error);
      throw new Error(`HTTP request failed: ${error.message}`);
    }
  }

  /**
   * Get credential information - equivalent to C# ServerSession.certificateInfo()
   */
  async getCredentialInfo(
    credentialID: string,
    agreementUUID?: string,
    certificate?: string,
    certInfoEnabled: boolean = false,
    authInfoEnabled: boolean = false,
  ): Promise<any> {
    this.logger.log('____________credentials/info____________');

    if (!this.bearerToken) {
      throw new UnauthorizedException('Not authenticated. Please login first.');
    }

    try {
      const credentialInfoRequest = {
        agreementUUID,
        credentialID,
        certificates: certificate,
        certInfoEnabled,
        authInfoEnabled,
        lang: 'VN',
      };

      const response = await this.sendCredentialInfoRequest(
        credentialInfoRequest,
      );

      if (response.error === 3005 || response.error === 3006) {
        // Token expired or invalid - retry login and retry request
        this.logger.log('Token expired, attempting to relogin...');
        await this.login(
          process.env.DIGITAL_SIGNATURE_RELYING_PARTY_USER || '',
          process.env.DIGITAL_SIGNATURE_RELYING_PARTY_PASSWORD || '',
        );
        return this.getCredentialInfo(
          credentialID,
          agreementUUID,
          certificate,
          certInfoEnabled,
          authInfoEnabled,
        );
      } else if (response.error !== 0) {
        throw new UnauthorizedException(response.errorDescription);
      }

      // Process the response similar to C# implementation
      if (response.cert) {
        response.cert.authorizationEmail = response.authorizationEmail;
        response.cert.authorizationPhone = response.authorizationPhone;
        response.cert.sharedMode = response.sharedMode;
        response.cert.createdRP = response.createdRP;
        response.cert.authModes = response.authModes;
        response.cert.authMode = response.authMode;
        response.cert.SCAL = response.SCAL;
        response.cert.contractExpirationDate = response.contractExpirationDate;
        response.cert.defaultPassphraseEnabled =
          response.defaultPassphraseEnabled;
        response.cert.trialEnabled = response.trialEnabled;
      }

      return response;
    } catch (error) {
      this.logger.error('Failed to get credential info', error);
      throw error;
    }
  }

  /**
   * Send credential info request to credentials/info endpoint
   */
  private async sendCredentialInfoRequest(
    credentialInfoRequest: any,
  ): Promise<any> {
    const baseUrl = this.configService.get<string>('DIGITAL_SIGNATURE_URL');
    const url = `${baseUrl}/credentials/info`;

    try {
      const response = await firstValueFrom(
        this.httpService.post(url, credentialInfoRequest, {
          headers: {
            Authorization: this.bearerToken,
            'Content-Type': 'application/json',
          },
        }),
      );

      return response.data;
    } catch (error) {
      this.logger.error('HTTP request failed for credential info', error);
      throw new Error(`HTTP request failed: ${error.message}`);
    }
  }

  /**
   * Authorize credential for signing - equivalent to C# ServerSession.authorize()
   */
  async authorizeCredential(
    agreementUUID: string,
    credentialID: string,
    numSignatures: number,
    documentDigests?: any,
    signAlgo?: any,
    authorizeCode?: string,
    mobileDisplayTemplate?: any,
  ): Promise<string> {
    this.logger.log('____________credentials/authorize____________');

    if (!this.bearerToken) {
      throw new UnauthorizedException('Not authenticated. Please login first.');
    }

    try {
      const authorizeRequest = {
        agreementUUID,
        credentialID,
        numSignatures,
        documentDigests,
        signAlgo,
        authorizeCode,
        lang: 'VN',
        validityPeriod: 300,
        operationMode: 'S', // Sign mode
        ...mobileDisplayTemplate, // Spread mobile display template properties
      };

      const response =
        await this.sendCredentialAuthorizeRequest(authorizeRequest);

      if (response.error === 3005 || response.error === 3006) {
        // Token expired or invalid - retry login and retry request
        this.logger.log('Token expired, attempting to relogin...');
        await this.login(
          process.env.DIGITAL_SIGNATURE_RELYING_PARTY_USER || '',
          process.env.DIGITAL_SIGNATURE_RELYING_PARTY_PASSWORD || '',
        );
        return this.authorizeCredential(
          agreementUUID,
          credentialID,
          numSignatures,
          documentDigests,
          signAlgo,
          authorizeCode,
          mobileDisplayTemplate,
        );
      } else if (response.error !== 0) {
        throw new UnauthorizedException(response.errorDescription);
      }

      return response.SAD; // Return Strong Authentication Data
    } catch (error) {
      this.logger.error('Failed to authorize credential', error);
      throw error;
    }
  }

  /**
   * Authorize credential with OTP - alternative flow
   */
  async authorizeCredentialWithOTP(
    agreementUUID: string,
    credentialID: string,
    numSignatures: number,
    documentDigests: any,
    signAlgo: any,
    otpRequestID: string,
    passCode: string,
  ): Promise<string> {
    this.logger.log('____________credentials/authorize (OTP)____________');

    if (!this.bearerToken) {
      throw new UnauthorizedException('Not authenticated. Please login first.');
    }

    try {
      const authorizeRequest = {
        agreementUUID,
        credentialID,
        numSignatures,
        documentDigests,
        signAlgo,
        requestID: otpRequestID,
        authorizeCode: passCode,
        lang: 'VN',
        validityPeriod: 300,
        operationMode: 'S', // Sign mode
      };

      const response =
        await this.sendCredentialAuthorizeRequest(authorizeRequest);

      if (response.error === 3005 || response.error === 3006) {
        // Token expired or invalid - retry login and retry request
        this.logger.log('Token expired, attempting to relogin...');
        await this.login(
          process.env.DIGITAL_SIGNATURE_RELYING_PARTY_USER || '',
          process.env.DIGITAL_SIGNATURE_RELYING_PARTY_PASSWORD || '',
        );
        return this.authorizeCredentialWithOTP(
          agreementUUID,
          credentialID,
          numSignatures,
          documentDigests,
          signAlgo,
          otpRequestID,
          passCode,
        );
      } else if (response.error !== 0) {
        throw new UnauthorizedException(response.errorDescription);
      }

      return response.SAD; // Return Strong Authentication Data
    } catch (error) {
      this.logger.error('Failed to authorize credential with OTP', error);
      throw error;
    }
  }

  /**
   * Send credential authorize request to credentials/authorize endpoint
   */
  private async sendCredentialAuthorizeRequest(
    authorizeRequest: any,
  ): Promise<any> {
    const baseUrl = this.configService.get<string>('DIGITAL_SIGNATURE_URL');
    const url = `${baseUrl}/credentials/authorize`;

    try {
      const response = await firstValueFrom(
        this.httpService.post(url, authorizeRequest, {
          headers: {
            Authorization: this.bearerToken,
            'Content-Type': 'application/json',
          },
        }),
      );

      return response.data;
    } catch (error) {
      this.logger.error('HTTP request failed for credential authorize', error);
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
