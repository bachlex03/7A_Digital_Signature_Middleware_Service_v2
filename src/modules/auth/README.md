# Auth Module

This module provides authentication functionality for the Digital Signature Middleware Service, converted from the C# implementation.

## Features

- **PKCS#12 Key Management**: Automatically loads and manages private keys from .p12 files
- **SSL2 Header Generation**: Creates SSL2 authorization headers with PKCS#1 signatures
- **Automatic Retry Logic**: Handles token expiration with automatic retry (up to 5 attempts)
- **Token Management**: Manages access tokens and refresh tokens
- **Thread-Safe Operations**: Ensures thread safety for concurrent requests

## API Endpoints

### POST /auth/login

Authenticates a user and returns access/refresh tokens.

**Request Body:**

```json
{
  "username": "your_username",
  "password": "your_password"
}
```

**Response:**

```json
{
  "error": 0,
  "errorDescription": "Success",
  "responseID": "response_id",
  "accessToken": "access_token",
  "refreshToken": "refresh_token"
}
```

### POST /auth/logout

Logs out the current user and clears all tokens.

### GET /auth/status

Returns the current authentication status.

### POST /auth/credentials/list

Retrieves a list of credentials/certificates.

**Request Body:**

```json
{
  "agreementUUID": "optional-agreement-uuid",
  "certificates": "optional-certificate-filter",
  "certInfoEnabled": false,
  "authInfoEnabled": false,
  "searchConditions": {
    "searchText": "optional-search-text",
    "status": "optional-status-filter",
    "type": "optional-type-filter"
  },
  "lang": "VN"
}
```

**Response:**

```json
{
  "error": 0,
  "errorDescription": "Success",
  "responseID": "response_id",
  "certs": [
    {
      "credentialID": "credential_id",
      "status": "active",
      "type": "certificate_type",
      "issuer": "issuer_name",
      "subject": "subject_name",
      "validFrom": "2024-01-01",
      "validTo": "2025-01-01",
      "serialNumber": "serial_number",
      "thumbprint": "thumbprint_hash"
    }
  ]
}
```

### POST /auth/credentials/info

Retrieves detailed information about a specific credential/certificate.

**Request Body:**

```json
{
  "credentialID": "required-credential-id",
  "agreementUUID": "optional-agreement-uuid",
  "certificates": "optional-certificate-filter",
  "certInfoEnabled": false,
  "authInfoEnabled": false,
  "lang": "VN"
}
```

**Response:**

```json
{
  "error": 0,
  "errorDescription": "Success",
  "responseID": "response_id",
  "cert": {
    "credentialID": "credential_id",
    "status": "active",
    "type": "certificate_type",
    "issuer": "issuer_name",
    "subject": "subject_name",
    "validFrom": "2024-01-01",
    "validTo": "2025-01-01",
    "serialNumber": "serial_number",
    "thumbprint": "thumbprint_hash",
    "authorizationEmail": "user@example.com",
    "authorizationPhone": "+1234567890",
    "sharedMode": "shared",
    "createdRP": "relying_party_name",
    "authModes": ["SMS", "EMAIL"],
    "authMode": "SMS",
    "SCAL": 2,
    "contractExpirationDate": "2025-12-31",
    "defaultPassphraseEnabled": true,
    "trialEnabled": false,
    "multisign": 1,
    "remainingSigningCounter": 100
  },
  "sharedMode": "shared",
  "createdRP": "relying_party_name",
  "authModes": ["SMS", "EMAIL"],
  "authMode": "SMS",
  "SCAL": 2,
  "contractExpirationDate": "2025-12-31",
  "defaultPassphraseEnabled": true,
  "trialEnabled": false,
  "multisign": 1,
  "remainingSigningCounter": 100,
  "authorizationEmail": "user@example.com",
  "authorizationPhone": "+1234567890"
}
```

### POST /auth/credentials/authorize

Authorizes a credential for signing operations.

**Request Body:**

```json
{
  "agreementUUID": "required-agreement-uuid",
  "credentialID": "required-credential-id",
  "numSignatures": 1,
  "documentDigests": {
    "hashes": ["hash1", "hash2"],
    "algorithm": "SHA256"
  },
  "signAlgo": "SHA256",
  "authorizeCode": "optional-authorization-code",
  "notificationMessage": "Please authorize this transaction",
  "messageCaption": "Transaction Authorization",
  "message": "You are about to sign important documents",
  "logoURI": "https://example.com/logo.png",
  "bgImageURI": "https://example.com/background.png",
  "rpIconURI": "https://example.com/rp-icon.png",
  "rpName": "Your Company Name",
  "vcEnabled": true,
  "acEnabled": true,
  "scaIdentity": "user@example.com",
  "lang": "VN",
  "requestID": "optional-otp-request-id"
}
```

**Response:**

```json
{
  "SAD": "strong_authentication_data_token"
}
```

**Note:** The endpoint supports two flows:

1. **Regular Authorization**: Uses mobile display template for user interaction
2. **OTP Authorization**: Uses requestID and authorizeCode for OTP-based authentication

## Environment Variables

Required environment variables:

```bash
# Digital Signature Service
DIGITAL_SIGNATURE_URL=https://your-api-domain.com/api
DIGITAL_SIGNATURE_RELYING_PARTY=your_relying_party
DIGITAL_SIGNATURE_RELYING_PARTY_USER=your_username
DIGITAL_SIGNATURE_RELYING_PARTY_PASSWORD=your_password
DIGITAL_SIGNATURE_RELYING_PARTY_SIGNATURE=your_signature

# SSL Configuration
SSL_P12_PATH=path/to/your/keystore.p12
SSL_P12_PASSWORD=your_p12_password
```

## Usage Example

```typescript
import { AuthService } from './modules/auth';

@Injectable()
export class YourService {
  constructor(private readonly authService: AuthService) {}

  async authenticate() {
    try {
      const response = await this.authService.login('username', 'password');
      console.log('Access Token:', response.accessToken);

      // Check if authenticated
      if (this.authService.isAuthenticated()) {
        const token = this.authService.getBearerToken();
        // Use token for authenticated requests
      }
    } catch (error) {
      console.error('Authentication failed:', error);
    }
  }

  async getCredentials() {
    try {
      // Get all credentials
      const allCredentials = await this.authService.getListCredentials();

      // Get credentials with filters
      const filteredCredentials = await this.authService.getListCredentials(
        'agreement-uuid',
        'certificate-filter',
        true, // certInfoEnabled
        true, // authInfoEnabled
        { searchText: 'search-term' },
      );

      return filteredCredentials;
    } catch (error) {
      console.error('Failed to get credentials:', error);
    }
  }

  async getCredentialInfo() {
    try {
      // Get credential info with minimal parameters
      const credentialInfo =
        await this.authService.getCredentialInfo('credential-id');

      // Get credential info with all parameters
      const detailedCredentialInfo = await this.authService.getCredentialInfo(
        'credential-id',
        'agreement-uuid',
        'certificate-filter',
        true, // certInfoEnabled
        true, // authInfoEnabled
      );

      return detailedCredentialInfo;
    } catch (error) {
      console.error('Failed to get credential info:', error);
    }
  }

  async authorizeCredential() {
    try {
      // Regular authorization with mobile display template
      const SAD = await this.authService.authorizeCredential(
        'agreement-uuid',
        'credential-id',
        1, // numSignatures
        { hashes: ['hash1', 'hash2'], algorithm: 'SHA256' }, // documentDigests
        'SHA256', // signAlgo
        'auth-code', // authorizeCode
        {
          notificationMessage: 'Please authorize this transaction',
          messageCaption: 'Transaction Authorization',
          message: 'You are about to sign important documents',
          logoURI: 'https://example.com/logo.png',
          rpName: 'Your Company Name',
          vcEnabled: true,
          acEnabled: true,
        },
      );

      // OTP-based authorization
      const SADWithOTP = await this.authService.authorizeCredentialWithOTP(
        'agreement-uuid',
        'credential-id',
        1, // numSignatures
        { hashes: ['hash1', 'hash2'], algorithm: 'SHA256' }, // documentDigests
        'SHA256', // signAlgo
        'otp-request-id', // otpRequestID
        '123456', // passCode
      );

      return { SAD, SADWithOTP };
    } catch (error) {
      console.error('Failed to authorize credential:', error);
    }
  }
}
```

## SSL2 Header Format

The service generates SSL2 headers in the format:

```
SSL2 BASE64(username:password:signature:timestamp:pkcs1Signature), Basic BASE64(USERNAME:username:password)
```

Where:

- `username`, `password`, `signature`: From relying party configuration
- `timestamp`: Current epoch time in milliseconds
- `pkcs1Signature`: SHA-256 hash signed with private key from .p12 file

## Error Handling

- **3005/3006**: Token expired/invalid - automatically retries
- **Other errors**: Throws UnauthorizedException with error description
- **Max retries**: 5 attempts before giving up
- **Private key errors**: Throws error during initialization
