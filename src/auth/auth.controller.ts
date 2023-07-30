// src/auth/auth.controller.ts
import { Body, Controller, Get, Post, Res, UseGuards } from '@nestjs/common';
import { ApiTags } from '@nestjs/swagger';
import { Response } from 'express';
import { UserService } from 'src/user/user.service';
import { AuthService } from './auth.service';
import { LoginDto } from './dto/login.dto';
import { NewPasswordDto } from './dto/new-password.dto';
import { CodeDto, ConfirmSignUpDto } from './dto/otp.dto';
import { SignUpDto } from './dto/signup.dto';
import { GetAccessToken } from './get-jwt.decorator';
import { GetCognitoUser } from './get-user.decorator';
import { JwtAuthGuard } from './jwt-auth.guard';
import { AWSCognitoPayload } from './models/AwsCognitoPayload';

@ApiTags('auth')
@Controller('auth')
export class AuthController {
  constructor(
    private authService: AuthService,
    private userService: UserService,
  ) {}

  @UseGuards(JwtAuthGuard)
  @Get('google/redirect')
  async googleLoginRedirect(
    @GetCognitoUser() user: AWSCognitoPayload,
    @Res() res: Response,
  ) {
    const appUser = await this.userService.getUserByCognitoId(user.sub);
    if (appUser) {
      throw new Error('User already exists');
    }
    await this.userService.create(user.sub);
    return res.redirect(`${process.env.LOGIN_REDIRECT_UI_URL}`);
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
