export enum AuthMode {
  SMS = 'SMS',
  EMAIL = 'EMAIL',
  BIOMETRIC = 'BIOMETRIC',
  PASSWORD = 'PASSWORD',
}

export class CertificateInfoDto {
  credentialID: string;
  status: string;
  type: string;
  issuer: string;
  subject: string;
  validFrom: string;
  validTo: string;
  serialNumber: string;
  thumbprint: string;

  // Additional fields from C# implementation
  authorizationEmail?: string;
  authorizationPhone?: string;
  sharedMode?: string;
  createdRP?: string;
  authModes?: string[];
  authMode?: AuthMode;
  SCAL?: number;
  contractExpirationDate?: string;
  defaultPassphraseEnabled?: boolean;
  trialEnabled?: boolean;
  multisign?: number;
  remainingSigningCounter?: number;
}

export class CredentialInfoResponseDto {
  error: number;
  errorDescription: string;
  responseID: string;
  cert: CertificateInfoDto;

  // Additional response fields
  sharedMode: string;
  createdRP: string;
  authModes: string[];
  authMode: AuthMode;
  SCAL: number;
  contractExpirationDate: string;
  defaultPassphraseEnabled: boolean;
  trialEnabled: boolean;
  multisign: number;
  remainingSigningCounter: number;
  authorizationEmail: string;
  authorizationPhone: string;
}
