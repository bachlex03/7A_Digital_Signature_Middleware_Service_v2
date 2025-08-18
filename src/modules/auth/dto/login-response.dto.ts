export class LoginResponseDto {
  error: number;
  errorDescription: string;
  responseID: string;
  accessToken: string;
  refreshToken?: string;
}
