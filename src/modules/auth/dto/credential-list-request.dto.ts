import { IsString, IsBoolean, IsOptional } from 'class-validator';

export class SearchConditionsDto {
  @IsOptional()
  @IsString()
  searchText?: string;

  @IsOptional()
  @IsString()
  status?: string;

  @IsOptional()
  @IsString()
  type?: string;
}

export class CredentialListRequestDto {
  @IsOptional()
  @IsString()
  agreementUUID?: string;

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
  searchConditions?: SearchConditionsDto;

  @IsOptional()
  @IsString()
  lang?: string;
}
