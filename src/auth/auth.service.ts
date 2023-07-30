// src/auth/auth.service.ts

import { ChallengeNameType } from '@aws-sdk/client-cognito-identity-provider';
import { Injectable } from '@nestjs/common';
import { CognitoService } from './cognito/cognito.service';
import { ConfirmSignUpDto } from './dto/otp.dto';
import { SignUpDto } from './dto/signup.dto';
@Injectable()
export class AuthService {
  constructor(private cognitoService: CognitoService) {}
  async login(usernameOrEmail: string, password: string) {
    const { ChallengeName, AuthenticationResult, Session } =
      await this.cognitoService.initiateAuth(usernameOrEmail, password);

    // * user first time login will require reset password
    if (ChallengeName === ChallengeNameType.NEW_PASSWORD_REQUIRED) {
      return {
        challengeName: ChallengeName,
        session: Session,
      };
    }

    if (!AuthenticationResult)
      throw new Error('Error, failed to get AuthenticationResult');

    return {
      accessToken: AuthenticationResult.AccessToken,
      idToken: AuthenticationResult.IdToken,
      refreshToken: AuthenticationResult.RefreshToken,
    };
  }

  async signUp(signUpDto: SignUpDto) {
    const response = await this.cognitoService.signUp(signUpDto);
    return response;
  }

  async sendSMS(username: string) {
    const response = await this.cognitoService.sendSMS(username);
    return response;
  }

  async confirmSmsSignUp(confirmSignUpDto: ConfirmSignUpDto) {
    return await this.cognitoService.confirmSignUp(confirmSignUpDto);
  }

  async sendEmailVerificationCode(accessToken: string) {
    return await this.cognitoService.sendEmailVerificationCode(accessToken);
  }

  async confirmEmail(accessToken: string, code: string) {
    return await this.cognitoService.verifyUserAttribute({
      AccessToken: accessToken,
      AttributeName: 'email',
      Code: code,
    });
  }

  async respondToAuthChallenge(
    email: string,
    newPassword: string,
    session: string,
  ) {
    const response = await this.cognitoService.respondToAuthChallenge(
      email,
      newPassword,
      session,
    );

    const { AuthenticationResult } = response;
    if (!AuthenticationResult)
      throw new Error('Error, failed to get AuthenticationResult');

    return {
      accessToken: AuthenticationResult.AccessToken,
      idToken: AuthenticationResult.IdToken,
      refreshToken: AuthenticationResult.RefreshToken,
    };
  }
}
