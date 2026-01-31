import {
  Controller,
  Get,
  Query,
  HttpException,
  HttpStatus,
  ValidationPipe,
  UsePipes,
  Req,
  Logger,
  Headers,
} from '@nestjs/common';
import { ApiTags, ApiOperation, ApiResponse } from '@nestjs/swagger';
import type { Request } from 'express';
import { ChallengeService } from './challenge.service';
import { GenerateChallengeDto, ChallengeResponseDto } from './altcha.dto';
import { trace, Span } from '@opentelemetry/api';
import { IpService } from './ip.service';

const tracer = trace.getTracer('challenge-controller');

@ApiTags('captcha')
@Controller('captcha')
@UsePipes(new ValidationPipe({ transform: true }))
export class ChallengeController {
  private readonly log = new Logger(ChallengeController.name);

  constructor(
    private readonly challengeService: ChallengeService,
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

  @Get('challenge')
  @ApiOperation({
    summary: 'Generate ALTCHA challenge',
    description:
      'Generates a new ALTCHA challenge for the specified domain. The difficulty is automatically adjusted based on threat detection and IP history. Domain can be provided via query parameter or inferred from Referer/Origin header.',
  })
  @ApiResponse({
    status: 200,
    description: 'Challenge generated successfully',
    type: ChallengeResponseDto,
  })
  @ApiResponse({
    status: 400,
    description: 'Invalid domain or domain not configured',
  })
  async generateChallenge(
    @Query() dto: GenerateChallengeDto,
    @Headers('referer') referer: string,
    @Headers('origin') origin: string,
    @Req() request: Request,
  ): Promise<ChallengeResponseDto> {
    const generateChallengeSpan = async (span: Span) => {
      try {
        const ip = this.ipService.extractIp(request);
        const domain = this.extractDomain(dto.domain, referer, origin);

        span.setAttribute('domain', domain);
        span.setAttribute('ip', ip);

        this.log.log(`Generating challenge for domain: ${domain}, IP: ${ip}`);

        const challenge = await this.challengeService.generateChallenge({
          domain,
          ip,
        });

        this.log.debug(
          `Challenge generated for domain: ${domain}, requiresCode: ${challenge.requiresCode}`,
        );
        span.setStatus({ code: 1 }); // OK
        return challenge;
      } catch (error) {
        const message =
          error instanceof Error
            ? error.message
            : 'Failed to generate challenge';
        this.log.error(
          `Failed to generate challenge: ${message}`,
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
    };

    return tracer.startActiveSpan(
      'generate-challenge',
      generateChallengeSpan,
    ) as Promise<ChallengeResponseDto>;
  }
}
