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
