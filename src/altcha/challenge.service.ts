import { Injectable, Logger, HttpException, HttpStatus } from '@nestjs/common';
import { createChallenge } from 'altcha-lib';
import { BaseConfigService } from '../config/base.config';
import { RedisService } from '../redis/redis.service';
import { CrowdSecService, ThreatLevel } from '../crowdsec/crowdsec.service';
import { MetricsService } from '../telemetry/metrics.service';
import { AbuseIPDBService } from '../abuseipdb/abuseipdb.service';
import { SpamhausService } from '../spamhaus/spamhaus.service';
import { randomBytes } from 'crypto';
import * as svgCaptcha from 'svg-captcha';

interface Challenge {
  algorithm: string;
  challenge: string;
  maxnumber?: number; // Note: altcha-lib uses lowercase 'maxnumber'
  salt: string;
  signature: string;
}

export interface ChallengeRequest {
  domain: string;
  ip: string;
}

export interface ChallengeResponse {
  challenge: string;
  maxNumber: number;
  salt: string;
  algorithm: string;
  signature: string;
  requiresCode: boolean;
  strength: number;
  codeChallenge?: {
    image: string;
    length: number;
    audio?: string;
  };
}

@Injectable()
export class ChallengeService {
  private readonly log = new Logger(ChallengeService.name);

  constructor(
    private readonly config: BaseConfigService,
    private readonly redisService: RedisService,
    private readonly crowdSecService: CrowdSecService,
    private readonly metricsService: MetricsService,
    private readonly abuseIPDBService: AbuseIPDBService,
    private readonly spamhausService: SpamhausService,
  ) {}

  async generateChallenge(
    request: ChallengeRequest,
  ): Promise<ChallengeResponse> {
    this.log.debug(
      `Generating challenge for domain ${request.domain}, IP: ${request.ip}`,
    );
    // Try to find domain by name first (if domain param is provided),
    // then by origin (if extracted from headers)
    let domainCfg = this.config.domain.getDomainConfig(request.domain);
    if (!domainCfg) {
      domainCfg = this.config.domain.findByOrigin(request.domain);
    }

    if (!domainCfg) {
      this.log.warn(`Domain ${request.domain} not configured`);
      throw new HttpException(
        `Domain ${request.domain} not configured`,
        HttpStatus.BAD_REQUEST,
      );
    }

    if (!domainCfg.key) {
      this.log.error(`Domain ${request.domain} has no key configured`);
      throw new HttpException(
        `Domain ${request.domain} has no key configured`,
        HttpStatus.INTERNAL_SERVER_ERROR,
      );
    }

    // Calculate dynamic strength based on threat level and IP history
    const strength = await this.calculateStrength(
      request.ip,
      request.domain,
      domainCfg.minStrength,
      domainCfg.maxStrength,
    );
    this.log.debug(
      `Calculated strength ${strength} for IP ${request.ip} on domain ${request.domain}`,
    );

    // Generate salt with timestamp and random data
    const timestamp = Date.now();
    const random = randomBytes(8).toString('hex');
    const maxNumber = this.strengthToMaxNumber(strength);

    // Calculate expiration time based on domain configuration
    const expirationTime = new Date(
      timestamp + domainCfg.challengeExpiresSeconds * 1000,
    );

    // If code verification is required, add codeChallenge parameter
    // This helps the widget understand the challenge structure
    const requiresCode =
      domainCfg.codeVerificationIfStrengthGT >= 0 &&
      strength >= domainCfg.codeVerificationIfStrengthGT;

    // Build salt with query parameters for code challenge support
    // Format: timestamp-random?edk=...&codeChallenge=...&expires=...
    const saltParams = `${timestamp}-${random}`;
    const challengeParams: Record<string, string> = {};
    let codeChallengeId: string | undefined;

    if (requiresCode) {
      // Generate EDK (Encrypted Decryption Key) for code challenge verification
      // This ensures the widget can properly validate code challenges
      const edk = randomBytes(16).toString('hex');
      codeChallengeId = randomBytes(32).toString('base64url');
      challengeParams.edk = edk;
      challengeParams.codeChallenge = codeChallengeId;
    }

    // Create ALTCHA challenge with expiration
    const challenge: Challenge = await createChallenge({
      hmacKey: domainCfg.key,
      salt: saltParams,
      maxNumber: maxNumber,
      expires: expirationTime,
      params: challengeParams,
    });

    // Store challenge data in Redis for validation
    const challengeId = challenge.challenge;
    await this.redisService.storeChallengeData(challengeId, {
      domain: request.domain,
      strength,
      createdAt: timestamp,
      ip: request.ip,
    });

    // Generate SVG CAPTCHA image if required
    let codeChallenge:
      | { image: string; length: number; audio?: string }
      | undefined;
    if (requiresCode && codeChallengeId) {
      const captcha = svgCaptcha.create({
        size: domainCfg.codeVerificationLength,
        noise: 2,
        color: true,
        background: '#ffffff',
        ignoreChars: '0o1ilI',
        width: 180,
        height: 50,
      });

      // Convert SVG to base64 data URI
      const svgBase64 = Buffer.from(captcha.data).toString('base64');
      const imageDataUri = `data:image/svg+xml;base64,${svgBase64}`;

      codeChallenge = {
        image: imageDataUri,
        length: domainCfg.codeVerificationLength,
        audio: `/espeak/${codeChallengeId}.wav`,
      };

      // Store the verification code (from SVG) linked to this challenge
      // CRITICAL: We store the code in Redis but NEVER send it to client
      await this.redisService.storeVerificationCode(challengeId, {
        code: captcha.text,
        domain: request.domain,
        ip: request.ip,
        strength,
      });
      await this.redisService.storeVerificationCode(codeChallengeId, {
        code: captcha.text,
        domain: request.domain,
        ip: request.ip,
        strength,
      });

      this.log.debug(
        `Generated SVG CAPTCHA for high-threat challenge (strength: ${strength})`,
      );
    }

    // Update IP stats to track challenge requests
    // This increases the threat level for IPs requesting many challenges
    await this.redisService.incrementIpChallengeRequests(
      request.ip,
      request.domain,
    );

    // Record metrics
    this.metricsService.recordCaptchaGenerated(request.domain, strength);

    this.log.debug(
      `Challenge generated successfully for domain ${request.domain}, requiresCode: ${requiresCode}, strength: ${strength}`,
    );

    // Ensure all required fields are present in the response
    // TypeScript narrowing: all fields are guaranteed to have values
    const challengeMaxNumber: number = challenge.maxnumber ?? maxNumber;
    const challengeSalt: string = challenge.salt;
    const challengeAlgorithm: string = challenge.algorithm;
    const challengeSignature: string = challenge.signature;

    // Build response with both maxNumber and maxnumber for compatibility
    // altcha-lib returns maxnumber (lowercase), but clients expect maxNumber (camelCase)
    const response: any = {
      challenge: challenge.challenge,
      maxNumber: challengeMaxNumber,
      maxnumber: challengeMaxNumber, // Include lowercase variant for SDK compatibility
      salt: challengeSalt,
      algorithm: challengeAlgorithm,
      signature: challengeSignature,
      requiresCode,
      strength,
      codeChallenge,
    };

    return response as ChallengeResponse;
  }

  private async calculateStrength(
    ip: string,
    domain: string,
    minStrength: number,
    maxStrength: number,
  ): Promise<number> {
    let baseStrength = minStrength;

    // Get domain config for security checks
    // Try to find domain by name first, then by origin
    let domainCfg = this.config.domain.getDomainConfig(domain);
    if (!domainCfg) {
      domainCfg = this.config.domain.findByOrigin(domain);
    }
    if (!domainCfg) {
      return Math.max(minStrength, Math.min(maxStrength, baseStrength));
    }

    // Check AbuseIPDB if enabled for this domain
    if (domainCfg.enableAbuseIPDB && this.config.abuseipdb.checkEnabled) {
      try {
        const abuseResult = await this.abuseIPDBService.checkIP(ip);
        if (abuseResult.isListed) {
          baseStrength += this.config.abuseipdb.strengthIncrease;
          this.log.log(
            `IP ${ip} found in AbuseIPDB (confidence: ${abuseResult.abuseConfidenceScore}%), increasing strength by ${this.config.abuseipdb.strengthIncrease}`,
          );
        }
      } catch (error) {
        this.log.warn(
          `AbuseIPDB check failed for IP ${ip}: ${error instanceof Error ? error.message : 'Unknown error'}`,
        );
      }
    }

    // Check Spamhaus if enabled for this domain
    if (domainCfg.enableSpamhaus && this.config.spamhaus.enabled) {
      try {
        const spamhausResult = await this.spamhausService.checkIP(ip);
        if (spamhausResult.isListed) {
          baseStrength += this.config.spamhaus.strengthIncrease;
          this.log.log(
            `IP ${ip} found in Spamhaus (${spamhausResult.lists.join(', ')}), increasing strength by ${this.config.spamhaus.strengthIncrease}`,
          );
        }
      } catch (error) {
        this.log.warn(
          `Spamhaus check failed for IP ${ip}: ${error instanceof Error ? error.message : 'Unknown error'}`,
        );
      }
    }

    // Check CrowdSec threat level with timeout and error handling
    try {
      const threatInfo = await Promise.race([
        this.crowdSecService.checkIpThreat(ip),
        new Promise<{ level: ThreatLevel; strengthIncrease: number }>(
          (resolve) =>
            setTimeout(
              () => resolve({ level: ThreatLevel.NONE, strengthIncrease: 0 }),
              500,
            ),
        ),
      ]);

      if (threatInfo.level !== ThreatLevel.NONE) {
        baseStrength += threatInfo.strengthIncrease;
        this.log.debug(
          `Threat detected for IP ${ip}: level ${threatInfo.level}, increasing strength by ${threatInfo.strengthIncrease}`,
        );
        this.metricsService.recordThreatDetection(
          ip,
          threatInfo.level,
          threatInfo.strengthIncrease,
        );
      }
    } catch (error) {
      const errorMessage =
        error instanceof Error ? error.message : 'Unknown error';
      this.log.warn(`CrowdSec check failed for IP ${ip}: ${errorMessage}`);

      // Check fail-open configuration
      if (!this.config.crowdsec.failOpen) {
        this.log.error('CrowdSec fail-closed is enabled, throwing error');
        throw new HttpException(
          'Threat detection service unavailable',
          HttpStatus.SERVICE_UNAVAILABLE,
        );
      }
      // Fail open - continue with base strength
      this.log.debug('Failing open - continuing with base strength');
    }

    // Check IP history from Redis
    const ipStats = await this.redisService.getIpStats(ip, domain);

    if (ipStats.attempts > 0) {
      const failureRate = ipStats.failures / ipStats.attempts;

      // Increase strength based on failure rate (configurable thresholds and increases)
      if (failureRate > domainCfg.highFailureRateThreshold) {
        baseStrength += domainCfg.highFailureRateIncrease;
        this.log.debug(
          `High failure rate detected (${(failureRate * 100).toFixed(1)}%), increasing strength by ${domainCfg.highFailureRateIncrease}`,
        );
      } else if (failureRate > domainCfg.mediumFailureRateThreshold) {
        baseStrength += domainCfg.mediumFailureRateIncrease;
        this.log.debug(
          `Medium failure rate detected (${(failureRate * 100).toFixed(1)}%), increasing strength by ${domainCfg.mediumFailureRateIncrease}`,
        );
      }

      // Increase strength if there are many recent attempts (configurable)
      if (ipStats.attempts > domainCfg.manyAttemptsThreshold) {
        baseStrength += domainCfg.manyAttemptsIncrease;
        this.log.debug(
          `Many attempts detected (${ipStats.attempts}), increasing strength by ${domainCfg.manyAttemptsIncrease}`,
        );
      }
    }

    // Check challenge request count (requests without successful validation)
    if (ipStats.challengeRequests > 0) {
      // Calculate pending challenges (requested but not validated successfully)
      const pendingChallenges = Math.max(
        0,
        ipStats.challengeRequests - ipStats.successes,
      );

      // Increase strength based on pending challenges
      // Each pending challenge increases strength by the configured penalty
      if (pendingChallenges > 0) {
        const penaltyIncrease =
          pendingChallenges * domainCfg.challengeRequestPenalty;
        baseStrength += penaltyIncrease;
        this.log.debug(
          `IP ${ip} has ${pendingChallenges} pending challenges, increasing strength by ${penaltyIncrease}`,
        );
      }
    }

    // Ensure strength is within bounds
    return Math.max(minStrength, Math.min(maxStrength, baseStrength));
  }

  private strengthToMaxNumber(strength: number): number {
    // Map strength (0-100) to maxNumber using the configurable scaling factor
    // Example: strength 50 * scalingFactor 100000 = 5,000,000
    // Ensure minimum of 1000 to prevent edge cases with zero or very small values
    const maxNumber = Math.floor(
      strength * this.config.domain.challengeResponseScalingFactor,
    );
    return Math.max(1000, maxNumber);
  }
}
