export interface CognitoOAuth2TokenRequest {
  grant_type: string;
  client_id: string;
  code: string;
  redirect_uri: string;
}

export interface CognitoOAuth2TokenResponse {
  id_token: string;
  access_token: string;
  refresh_token: string;
  expires_in: number;
  token_type: string;
}
