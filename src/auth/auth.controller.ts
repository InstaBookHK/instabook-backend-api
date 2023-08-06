// src/auth/auth.controller.ts
import { Body, Controller, Post, UseGuards } from '@nestjs/common';
import { ApiResponse, ApiTags } from '@nestjs/swagger';
import { UserService } from 'src/user/user.service';
import { AuthService } from './auth.service';
import { ExchangeCodeResponse } from './dto/exchange-code.dto';
import { LoginDto } from './dto/login.dto';
import { NewPasswordDto } from './dto/new-password.dto';
import { CodeDto, ConfirmSignUpDto } from './dto/otp.dto';
import { SignUpDto } from './dto/signup.dto';
import { GetAccessToken } from './get-jwt.decorator';
import { JwtAuthGuard } from './jwt-auth.guard';

@ApiTags('auth')
@Controller('auth')
export class AuthController {
  constructor(
    private authService: AuthService,
    private userService: UserService,
  ) {}

  // TODO properly rename this endpoint
  // * add swagegr api response type
  // * add response type
  // * add response type
  @ApiResponse({
    status: 200,
    description: 'exchange code for token and get user / create user',
    type: ExchangeCodeResponse,
  })
  @Post('exchange-code')
  async exchangeCode(
    @Body('code') code: string,
  ): Promise<ExchangeCodeResponse> {
    const tokens = await this.authService.exchangeCodeForToken(code);
    // 1. using id_token to query user exist in db or not
    // 2. if user not exist, create user in db
    // 3. if user exist, return user with tokens as response
    const user = await this.userService.getUserByCognitoId(tokens.id_token);
    if (!user) {
      const newUser = await this.userService.create(tokens.id_token);
      return { user: newUser, tokens };
    }
    return { user, tokens };
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
