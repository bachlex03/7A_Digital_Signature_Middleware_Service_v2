export class BaseCertificateInfoDto {
  credentialID: string;
  status: string;
  type: string;
  issuer: string;
  subject: string;
  validFrom: string;
  validTo: string;
  serialNumber: string;
  thumbprint: string;
  // Add more fields as needed based on your API response
}

export class CredentialListResponseDto {
  error: number;
  errorDescription: string;
  responseID: string;
  certs: BaseCertificateInfoDto[];
}
