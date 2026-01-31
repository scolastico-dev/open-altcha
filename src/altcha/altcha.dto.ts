import {
  IsString,
  IsNotEmpty,
  IsOptional,
  IsObject,
  IsArray,
} from 'class-validator';
import { ApiProperty } from '@nestjs/swagger';

export class GenerateChallengeDto {
  @ApiProperty({
    description:
      'Domain identifier for which to generate the challenge (optional, can be inferred from Referer/Origin)',
    example: 'example',
    required: false,
  })
  @IsString()
  @IsOptional()
  domain?: string;
}

export class ValidateChallengeDto {
  @ApiProperty({
    description:
      'Domain identifier for which the challenge was generated (optional, can be inferred from Referer/Origin)',
    example: 'example',
    required: false,
  })
  @IsString()
  @IsOptional()
  domain?: string;

  @ApiProperty({
    description: 'Solution code from ALTCHA widget (for code-based challenges)',
    example: 'mOFZmZ',
    required: false,
  })
  @IsString()
  @IsOptional()
  code?: string;

  @ApiProperty({
    description:
      'ALTCHA solution payload (Base64-encoded JSON string from widget)',
    example:
      'eyJhbGdvcml0aG0iOiJTSEEtMjU2IiwiY2hhbGxlbmdlIjoiLi4uIiwibnVtYmVyIjoxMjM0NSwic2FsdCI6Ii4uLiIsInNpZ25hdHVyZSI6Ii4uLiJ9',
  })
  @IsString()
  @IsNotEmpty()
  payload: string;

  @ApiProperty({
    description: 'Verification code if required for high-threat scenarios',
    example: 'ABC123',
    required: false,
  })
  @IsString()
  @IsOptional()
  verificationCode?: string;

  @ApiProperty({
    description:
      'Additional form data for spam filtering (email, name, message, etc.)',
    example: { email: 'user@example.com', message: 'Hello world' },
    required: false,
  })
  @IsObject()
  @IsOptional()
  data?: Record<string, any>;

  @ApiProperty({
    description:
      'Email address from form (sent when content signing is enabled)',
    example: 'user@example.com',
    required: false,
  })
  @IsString()
  @IsOptional()
  email?: string;

  @ApiProperty({
    description:
      'Expected languages for spam detection (sent when content signing is enabled)',
    example: ['en', 'de'],
    required: false,
  })
  @IsArray()
  @IsOptional()
  expectedLanguages?: string[];

  @ApiProperty({
    description:
      'Form fields for spam filtering (sent when content signing is enabled)',
    example: { name: 'John Doe', message: 'Hello world' },
    required: false,
  })
  @IsObject()
  @IsOptional()
  fields?: Record<string, any>;

  @ApiProperty({
    description:
      'IP address for verification (sent when content signing is enabled)',
    example: 'auto',
    required: false,
  })
  @IsString()
  @IsOptional()
  ipAddress?: string;

  @ApiProperty({
    description: 'User timezone (sent when content signing is enabled)',
    example: 'Europe/Berlin',
    required: false,
  })
  @IsString()
  @IsOptional()
  timeZone?: string;
}

export class ChallengeResponseDto {
  @ApiProperty({
    description: 'The challenge hash',
    example: 'abc123...',
  })
  challenge: string;

  @ApiProperty({
    description:
      'Maximum number for the challenge (required for Proof-of-Work calculation, especially with code challenges)',
    example: 100000,
  })
  maxNumber: number;

  @ApiProperty({
    description:
      'Maximum number for the challenge - lowercase variant included for SDK compatibility',
    example: 100000,
  })
  maxnumber?: number;

  @ApiProperty({
    description:
      'Salt used for the challenge (includes timestamp, EDK, expiration, and codeChallenge flag in URL query format)',
    example:
      '1234567890-abc&expires=1234567890000&edk=base64encodedkey&codeChallenge=true',
  })
  salt: string;

  @ApiProperty({
    description: 'Algorithm used (SHA-256)',
    example: 'SHA-256',
  })
  algorithm: string;

  @ApiProperty({
    description: 'HMAC signature',
    example: 'signature...',
  })
  signature: string;

  @ApiProperty({
    description: 'Whether code verification is required',
    example: false,
  })
  requiresCode: boolean;

  @ApiProperty({
    description: 'The calculated strength level',
    example: 50,
  })
  strength: number;

  @ApiProperty({
    description:
      'Code challenge object containing SVG image data and audio path',
    example: {
      image: 'data:image/svg+xml;base64,PHN2Zy4uLg==',
      length: 6,
      audio: '/espeak/challenge-id.wav',
    },
    required: false,
  })
  codeChallenge?: {
    image: string;
    length: number;
    audio?: string;
  };
}

export class ValidationResponseDto {
  @ApiProperty({
    description: 'Whether the solution is valid',
    example: true,
  })
  verified: boolean;

  @ApiProperty({
    description:
      'Original ALTCHA payload (Base64-encoded JSON string from widget)',
    example:
      'eyJhbGdvcml0aG0iOiJTSEEtMjU2IiwiY2hhbGxlbmdlIjoiLi4uIiwibnVtYmVyIjoxMjM0NSwic2FsdCI6Ii4uLiIsInNpZ25hdHVyZSI6Ii4uLiJ9',
    required: false,
  })
  payload?: string;

  @ApiProperty({
    description: 'Verification data (payload) for backend validation',
    example: 'eyJhbGdvcml0aG0iOi4uLn0=',
    required: false,
  })
  verificationData?: string;

  @ApiProperty({
    description: 'HMAC signature of the verification data',
    example: 'abc123...',
    required: false,
  })
  signature?: string;

  @ApiProperty({
    description: 'Timestamp when verification was performed',
    example: 1706745600000,
    required: false,
  })
  time?: number;

  @ApiProperty({
    description: 'Algorithm used for the challenge',
    example: 'SHA-256',
    required: false,
  })
  algorithm?: string;

  @ApiProperty({
    description: 'Spam/threat score (0 = clean, higher = more suspicious)',
    example: 0,
    required: false,
  })
  score?: number;

  @ApiProperty({
    description: 'Reason code if validation fails or is suspicious',
    example: 'DISPOSABLE_EMAIL',
    required: false,
  })
  reason?: string;

  @ApiProperty({
    description: 'Validated form fields (prevents tampering)',
    example: { email: 'user@example.com', message: 'Hello' },
    required: false,
  })
  fields?: Record<string, any>;

  @ApiProperty({
    description: 'HTML response from forward host (if configured)',
    example: '<!DOCTYPE html>...',
    required: false,
  })
  forwardedHtml?: string;
}

export class VerifyBackendDto {
  @ApiProperty({
    description: 'Domain identifier',
    example: 'example',
    required: false,
  })
  @IsString()
  @IsOptional()
  domain?: string;

  @ApiProperty({
    description: 'Verification data from the Sentinel validation response',
    example: 'eyJhbGdvcml0aG0iOi4uLn0=',
  })
  @IsString()
  @IsNotEmpty()
  verificationData: string;

  @ApiProperty({
    description: 'Signature from the Sentinel validation response',
    example: 'abc123...',
  })
  @IsString()
  @IsNotEmpty()
  signature: string;

  @ApiProperty({
    description: 'Timestamp from the Sentinel validation response',
    example: 1706745600000,
  })
  @IsNotEmpty()
  time: number;

  @ApiProperty({
    description: 'The original user IP address (optional)',
    example: '192.168.1.1',
    required: false,
  })
  @IsString()
  @IsOptional()
  ip?: string;
}

export class VerifyBackendResponseDto {
  @ApiProperty({
    description: 'Whether the backend verification is valid',
    example: true,
  })
  valid: boolean;
}
