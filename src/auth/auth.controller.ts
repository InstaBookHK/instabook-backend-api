// src/auth/auth.controller.ts
import { Body, Controller, Post, UseGuards } from '@nestjs/common';
import { ApiTags } from '@nestjs/swagger';
import { AuthService } from './auth.service';
import { LoginDto } from './dto/login.dto';
import { NewPasswordDto } from './dto/new-password.dto';
import { CodeDto, ConfirmSignUpDto } from './dto/otp.dto';
import { SignUpDto } from './dto/signup.dto';
import { GetAccessToken } from './get-jwt.decorator';
import { JwtAuthGuard } from './jwt-auth.guard';

@ApiTags('auth')
@Controller('auth')
export class AuthController {
  constructor(private authService: AuthService) {}

  @Post('exchange-code')
  async exchangeCode(@Body('code') code: string) {
    const tokens = await this.authService.exchangeCodeForToken(code);
    // Here you can pass tokens to AuthService for any additional processing
    // For example:
    // await this.authService.handleAuthentication(tokens);
    return tokens;
  }

  @Post('login')
  login(@Body() loginDto: LoginDto) {
    return this.authService.login(loginDto.usernameOrEmail, loginDto.password);
  }

  @Post('signup')
  signUp(@Body() signUpDto: SignUpDto) {
    return this.authService.signUp(signUpDto);
  }

  @Post('send-sms')
  async sendSMS(@Body('username') username: string) {
    return this.authService.sendSMS(username);
  }

  @UseGuards(JwtAuthGuard)
  @Post('send-verification-email')
  async sendEmailVerificationCode(@GetAccessToken() accessToken: string) {
    return this.authService.sendEmailVerificationCode(accessToken);
  }

  @UseGuards(JwtAuthGuard)
  @Post('confirm-email')
  async confirmEmail(
    @GetAccessToken() accessToken: string,
    @Body() { code }: CodeDto,
  ) {
    return this.authService.confirmEmail(accessToken, code);
  }

  @Post('confirm-sms-signup')
  async confirmSmsSignUp(@Body() confirmSignUpDto: ConfirmSignUpDto) {
    return this.authService.confirmSmsSignUp(confirmSignUpDto);
  }

  @Post('respond-to-new-password-required')
  respondToNewPasswordRequired(@Body() newPasswordDto: NewPasswordDto) {
    return this.authService.respondToAuthChallenge(
      newPasswordDto.email,
      newPasswordDto.newPassword,
      newPasswordDto.session,
    );
  }
}
