import {
  Controller,
  Post,
  Body,
  HttpCode,
  HttpStatus,
  UseGuards,
  Get,
  Req,
} from '@nestjs/common';
import { AuthService } from './auth.service';
import { LoginRequestDto } from './dto/login-request.dto';
import { LoginResponseDto } from './dto/login-response.dto';
import { CredentialListRequestDto } from './dto/credential-list-request.dto';
import { CredentialInfoRequestDto } from './dto/credential-info-request.dto';

export class LoginDto {
  username: string;
  password: string;
}

@Controller('auth')
export class AuthController {
  constructor(private readonly authService: AuthService) {}

  @Post('login')
  @HttpCode(HttpStatus.OK)
  async login(@Body() loginDto: LoginDto): Promise<LoginResponseDto> {
    return this.authService.login(loginDto.username, loginDto.password);
  }

  @Post('credentials/list')
  @HttpCode(HttpStatus.OK)
  async getListCredentials(
    @Body() dto: CredentialListRequestDto,
  ): Promise<any> {
    const {
      agreementUUID,
      certificates,
      certInfoEnabled,
      authInfoEnabled,
      searchConditions,
    } = dto;
    return this.authService.getListCredentials(
      agreementUUID,
      certificates,
      certInfoEnabled,
      authInfoEnabled,
      searchConditions,
    );
  }

  @Post('credentials/info')
  @HttpCode(HttpStatus.OK)
  async getCredentialInfo(@Body() dto: CredentialInfoRequestDto): Promise<any> {
    const {
      credentialID,
      agreementUUID,
      certificates,
      certInfoEnabled,
      authInfoEnabled,
    } = dto;
    return this.authService.getCredentialInfo(
      credentialID,
      agreementUUID,
      certificates,
      certInfoEnabled,
      authInfoEnabled,
    );
  }

  //   @Post('logout')
  //   @HttpCode(HttpStatus.OK)
  //   async logout(): Promise<{ message: string }> {
  //     this.authService.logout();
  //     return { message: 'Logged out successfully' };
  //   }

  //   @Get('status')
  //   @HttpCode(HttpStatus.OK)
  //   async getAuthStatus(): Promise<{
  //     authenticated: boolean;
  //     hasToken: boolean;
  //   }> {
  //     const isAuthenticated = this.authService.isAuthenticated();
  //     const hasToken = !!this.authService.getBearerToken();

  //     return {
  //       authenticated: isAuthenticated,
  //       hasToken: hasToken,
  //     };
  //   }
}
