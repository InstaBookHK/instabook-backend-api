import { User } from '@prisma/client';
import { CognitoOAuth2TokenResponse } from './TokenDto';

export class ExchangeCodeResponse {
  user: User;
  tokens: CognitoOAuth2TokenResponse;
}
