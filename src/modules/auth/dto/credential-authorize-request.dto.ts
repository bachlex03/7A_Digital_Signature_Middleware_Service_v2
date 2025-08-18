import {
  IsString,
  IsBoolean,
  IsOptional,
  IsNumber,
  IsArray,
} from 'class-validator';

export enum OperationMode {
  S = 'S', // Sign
  A = 'A', // Authorize
  V = 'V', // Verify
}

export enum SignAlgo {
  SHA1 = 'SHA1',
  SHA256 = 'SHA256',
  SHA512 = 'SHA512',
}

export class DocumentDigestsDto {
  @IsArray()
  @IsString({ each: true })
  hashes: string[];

  @IsOptional()
  @IsString()
  algorithm?: string;
}

export class ClientInfoDto {
  @IsOptional()
  @IsString()
  userAgent?: string;

  @IsOptional()
  @IsString()
  ipAddress?: string;

  @IsOptional()
  @IsString()
  deviceId?: string;
}

export class MobileDisplayTemplateDto {
  @IsOptional()
  @IsString()
  notificationMessage?: string;

  @IsOptional()
  @IsString()
  messageCaption?: string;

  @IsOptional()
  @IsString()
  message?: string;

  @IsOptional()
  @IsString()
  logoURI?: string;

  @IsOptional()
  @IsString()
  bgImageURI?: string;

  @IsOptional()
  @IsString()
  rpIconURI?: string;

  @IsOptional()
  @IsString()
  rpName?: string;

  @IsOptional()
  @IsBoolean()
  vcEnabled?: boolean;

  @IsOptional()
  @IsBoolean()
  acEnabled?: boolean;

  @IsOptional()
  @IsString()
  scaIdentity?: string;
}

export class CredentialAuthorizeRequestDto {
  @IsString()
  agreementUUID: string;

  @IsString()
  credentialID: string;

  @IsOptional()
  @IsString()
  authorizeCode?: string;

  @IsNumber()
  numSignatures: number;

  @IsOptional()
  documentDigests?: DocumentDigestsDto;

  @IsOptional()
  clientInfo?: ClientInfoDto;

  @IsOptional()
  @IsString()
  notificationMessage?: string;

  @IsOptional()
  @IsString()
  messageCaption?: string;

  @IsOptional()
  @IsString()
  message?: string;

  @IsOptional()
  @IsString()
  logoURI?: string;

  @IsOptional()
  @IsString()
  bgImageURI?: string;

  @IsOptional()
  @IsString()
  rpIconURI?: string;

  @IsOptional()
  @IsString()
  rpName?: string;

  @IsOptional()
  @IsBoolean()
  vcEnabled?: boolean;

  @IsOptional()
  @IsBoolean()
  acEnabled?: boolean;

  @IsOptional()
  operationMode?: OperationMode;

  @IsOptional()
  @IsString()
  scaIdentity?: string;

  @IsOptional()
  @IsString()
  responseURI?: string;

  @IsOptional()
  @IsNumber()
  validityPeriod?: number;

  @IsOptional()
  @IsArray()
  @IsString({ each: true })
  documents?: string[];

  @IsOptional()
  signAlgo?: SignAlgo;

  @IsOptional()
  @IsString()
  signAlgoParams?: string;

  @IsOptional()
  @IsString()
  lang?: string;

  // Additional fields for OTP flow
  @IsOptional()
  @IsString()
  requestID?: string;
}
