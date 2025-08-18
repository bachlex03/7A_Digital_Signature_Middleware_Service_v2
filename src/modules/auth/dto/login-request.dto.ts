import { IsBoolean, IsString, IsOptional } from 'class-validator';

export class LoginRequestDto {
  @IsBoolean()
  rememberMeEnabled: boolean;

  @IsString()
  relyingParty: string;

  @IsString()
  @IsOptional()
  lang?: string;
}
