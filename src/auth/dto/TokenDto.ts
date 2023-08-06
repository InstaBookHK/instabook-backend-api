import { ApiProperty } from '@nestjs/swagger';
import { IsNotEmpty, IsNumber, IsString } from 'class-validator';

export class CognitoOAuth2TokenRequest {
  @ApiProperty({ example: 'authorization_code' })
  @IsString()
  @IsNotEmpty()
  grant_type: string;

  @ApiProperty({ example: 'your-client-id' })
  @IsString()
  @IsNotEmpty()
  client_id: string;

  @ApiProperty({ example: 'your-auth-code' })
  @IsString()
  @IsNotEmpty()
  code: string;

  @ApiProperty({ example: 'your-redirect-uri' })
  @IsString()
  @IsNotEmpty()
  redirect_uri: string;
}

export class CognitoOAuth2TokenResponse {
  @ApiProperty({ example: 'your-id-token' })
  @IsString()
  @IsNotEmpty()
  id_token: string;

  @ApiProperty({ example: 'your-access-token' })
  @IsString()
  @IsNotEmpty()
  access_token: string;

  @ApiProperty({ example: 'your-refresh-token' })
  @IsString()
  @IsNotEmpty()
  refresh_token: string;

  @ApiProperty({ example: 3600 })
  @IsNumber()
  @IsNotEmpty()
  expires_in: number;

  @ApiProperty({ example: 'Bearer' })
  @IsString()
  @IsNotEmpty()
  token_type: string;
}
