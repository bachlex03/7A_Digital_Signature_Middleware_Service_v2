import { IsString, IsBoolean, IsOptional } from 'class-validator';

export class CredentialInfoRequestDto {
  @IsOptional()
  @IsString()
  agreementUUID?: string;

  @IsString()
  credentialID: string;

  @IsOptional()
  @IsString()
  certificates?: string;

  @IsOptional()
  @IsBoolean()
  certInfoEnabled?: boolean;

  @IsOptional()
  @IsBoolean()
  authInfoEnabled?: boolean;

  @IsOptional()
  @IsString()
  lang?: string;
}
