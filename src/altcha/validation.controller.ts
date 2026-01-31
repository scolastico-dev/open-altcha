import {
  Controller,
  Post,
  Body,
  HttpException,
  HttpStatus,
  HttpCode,
  ValidationPipe,
  UsePipes,
  Req,
  Logger,
  Headers,
} from '@nestjs/common';
import { ApiTags, ApiOperation, ApiResponse } from '@nestjs/swagger';
import type { Request } from 'express';
import { ValidationService } from './validation.service';
import {
  ValidateChallengeDto,
  ValidationResponseDto,
  VerifyBackendDto,
  VerifyBackendResponseDto,
} from './altcha.dto';
import { trace } from '@opentelemetry/api';
import { IpService } from './ip.service';

const tracer = trace.getTracer('validation-controller');

@ApiTags('captcha')
@Controller('captcha')
@UsePipes(new ValidationPipe({ transform: true }))
export class ValidationController {
  private readonly log = new Logger(ValidationController.name);

  constructor(
    private readonly validationService: ValidationService,
    private readonly ipService: IpService,
  ) {}

  /**
   * Extracts domain from query parameter, referer, or origin header.
   * Tries query parameter first, then referer, then origin.
   */
  private extractDomain(
    queryDomain: string | undefined,
    referer: string | undefined,
    origin: string | undefined,
  ): string {
    // If domain is provided in query, use it
    if (queryDomain) {
      return queryDomain;
    }

    // Try to extract from referer header
    if (referer) {
      try {
        const url = new URL(referer);
        // Extract hostname without port
        return url.hostname;
      } catch {
        this.log.warn(`Failed to parse referer header: ${referer}`);
      }
    }

    // Try to extract from origin header
    if (origin) {
      try {
        const url = new URL(origin);
        return url.hostname;
      } catch {
        this.log.warn(`Failed to parse origin header: ${origin}`);
      }
    }

    throw new HttpException(
      'Domain not specified and could not be inferred from headers',
      HttpStatus.BAD_REQUEST,
    );
  }

  @Post('validate')
  @HttpCode(200)
  @ApiOperation({
    summary: 'Validate ALTCHA solution and forward if configured',
    description:
      'Validates an ALTCHA solution. Each challenge can only be validated once to prevent replay attacks. Accepts either JSON body {"payload":"..."} or form data with altcha field. If forwardHost is configured for the domain, validated data will be forwarded to that host and the HTML response will be returned.',
  })
  @ApiResponse({
    status: 200,
    description: 'Validation result or forwarded HTML response',
    type: ValidationResponseDto,
  })
  @ApiResponse({
    status: 400,
    description: 'Invalid domain or payload format',
  })
  async validateChallenge(
    @Body() dto: ValidateChallengeDto,
    @Headers('referer') referer: string,
    @Headers('origin') origin: string,
    @Req() request: Request,
  ): Promise<ValidationResponseDto | string> {
    return tracer.startActiveSpan('validate-challenge', async (span) => {
      try {
        const ip = this.ipService.extractIp(request);
        const domain = this.extractDomain(dto.domain, referer, origin);

        span.setAttribute('domain', domain);
        span.setAttribute('ip', ip);

        this.log.log(`Validating challenge for domain: ${domain}, IP: ${ip}`);

        const result = await this.validationService.validateChallenge({
          domain,
          payload: dto.payload,
          ip,
          verificationCode: dto.code,
          data: dto.data,
        });

        this.log.log(
          `Challenge validation result for domain ${domain}, IP ${ip}: ${result.verified}`,
        );
        span.setAttribute('verified', result.verified);
        span.setStatus({ code: 1 }); // OK

        return result;
      } catch (error) {
        const message =
          error instanceof Error
            ? error.message
            : 'Failed to validate challenge';
        this.log.error(
          `Failed to validate challenge: ${message}`,
          error instanceof Error ? error.stack : undefined,
        );
        span.setStatus({ code: 2, message }); // ERROR
        if (error instanceof Error) {
          span.recordException(error);
        }

        throw new HttpException(message, HttpStatus.BAD_REQUEST);
      } finally {
        span.end();
      }
    });
  }

  @Post('verify')
  @HttpCode(200)
  @ApiOperation({
    summary: 'Verify ALTCHA solution from a backend',
    description:
      'Verifies a previously validated ALTCHA solution using the signature returned from POST /validate. This allows your backend to verify the CAPTCHA was solved without needing Redis. The signature is bound to the IP address (if verifyIpAddress is enabled), domain, and timestamp to prevent replay attacks. Each signature can only be used once.',
  })
  @ApiResponse({
    status: 200,
    description: 'Backend verification result',
    type: VerifyBackendResponseDto,
  })
  @ApiResponse({
    status: 400,
    description: 'Invalid verification data or signature',
  })
  async verifyBackend(
    @Body() dto: VerifyBackendDto,
    @Headers('referer') referer: string | undefined,
    @Headers('origin') origin: string | undefined,
    @Req() request: Request,
  ): Promise<VerifyBackendResponseDto> {
    return tracer.startActiveSpan('verify-backend', async (span) => {
      try {
        // Use the IP from dto (user's browser IP) if provided, otherwise use current request IP
        // Note: If IP comes from dto, it's already stripped (via /ip endpoint or validate response)
        // Only strip if we extract it from the current request
        const ip = dto.ip || this.ipService.extractIp(request);
        const domain = this.extractDomain(dto.domain, referer, origin);

        span.setAttribute('domain', domain);
        span.setAttribute('ip', ip);

        this.log.log(
          `Verifying backend submission for domain: ${domain}, IP: ${ip}`,
        );

        const valid = await this.validationService.verifyBackendSubmission(
          domain,
          dto.verificationData,
          dto.signature,
          dto.time,
          ip,
        );

        this.log.log(
          `Backend verification result for domain ${domain}, IP ${ip}: ${valid}`,
        );
        span.setAttribute('valid', valid);
        span.setStatus({ code: 1 }); // OK

        return { valid };
      } catch (error) {
        const message =
          error instanceof Error
            ? error.message
            : 'Failed to verify backend submission';
        this.log.error(
          `Failed to verify backend submission: ${message}`,
          error instanceof Error ? error.stack : undefined,
        );
        span.setStatus({ code: 2, message }); // ERROR
        if (error instanceof Error) {
          span.recordException(error);
        }

        throw new HttpException(message, HttpStatus.BAD_REQUEST);
      } finally {
        span.end();
      }
    });
  }
}
