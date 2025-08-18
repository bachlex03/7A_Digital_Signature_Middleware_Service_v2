export class CredentialAuthorizeResponseDto {
  error: number;
  errorDescription: string;
  responseID: string;

  // Main response fields
  SAD: string; // Strong Authentication Data
  expiresIn: number;
  remainingCounter: number;
  tempLockoutDuration: number;
}
