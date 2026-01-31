import { Injectable, Logger, HttpException, HttpStatus } from '@nestjs/common';
import { createChallenge, verifySolution } from 'altcha-lib';
import { BaseConfigService } from '../config/base.config';
import { RedisService } from '../redis/redis.service';
import { CrowdSecService, ThreatLevel } from '../crowdsec/crowdsec.service';
import { MetricsService } from '../telemetry/metrics.service';
import { AbuseIPDBService } from '../abuseipdb/abuseipdb.service';
import { SpamhausService } from '../spamhaus/spamhaus.service';
import { randomBytes, createHmac } from 'crypto';
import * as svgCaptcha from 'svg-captcha';
import * as disposableDomains from 'disposable-email-domains';
import stringify from 'fast-json-stable-stringify';

// Type definitions for altcha-lib
type Algorithm = 'SHA-1' | 'SHA-256' | 'SHA-512';

interface Challenge {
  challenge: string;
  maxNumber?: number;
  salt?: string;
  algorithm?: string;
  signature?: string;
}

interface Payload {
  algorithm: Algorithm;
  challenge: string;
  number: number;
  salt: string;
  signature: string;
}

export interface ChallengeRequest {
  domain: string;
  ip: string;
}

export interface ValidationRequest {
  domain: string;
  payload: string;
  ip: string;
  verificationCode?: string;
  data?: Record<string, any>;
}

export interface ValidationResponse {
  verified: boolean;
  verificationData?: string;
  signature?: string;
  time?: number;
  algorithm?: string;
  score?: number;
  reason?: string;
  fields?: Record<string, any>;
  forwardedHtml?: string;
}

export interface ChallengeResponse {
  challenge: string;
  maxNumber?: number;
  salt?: string;
  algorithm?: string;
  signature?: string;
  requiresCode: boolean;
  strength: number;
  codeChallenge?: {
    image: string;
    length: number;
    audio?: string;
  };
}

@Injectable()
export class AltchaService {
  private readonly log = new Logger(AltchaService.name);

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
    const salt = `${timestamp}-${random}`;

    // Calculate expiration time based on domain configuration
    const expirationTime = new Date(
      timestamp + domainCfg.challengeExpiresSeconds * 1000,
    );

    // Create ALTCHA challenge with expiration
    const challenge: Challenge = await createChallenge({
      hmacKey: domainCfg.key,
      salt,
      maxNumber: this.strengthToMaxNumber(strength),
      expires: expirationTime,
    });

    // Store challenge data in Redis for validation
    const challengeId = challenge.challenge;
    await this.redisService.storeChallengeData(challengeId, {
      domain: request.domain,
      strength,
      createdAt: timestamp,
      ip: request.ip,
    });

    // Check if code verification is required
    const requiresCode =
      domainCfg.codeVerificationIfStrengthGT >= 0 &&
      strength >= domainCfg.codeVerificationIfStrengthGT;

    // Generate SVG CAPTCHA image if required
    let codeChallenge:
      | { image: string; length: number; audio?: string }
      | undefined;
    if (requiresCode) {
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
        audio: `/espeak/${challengeId}.wav`,
      };

      // Store the verification code (from SVG) linked to this challenge
      // CRITICAL: We store the code in Redis but NEVER send it to client
      await this.redisService.storeVerificationCode(challengeId, {
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

    return {
      challenge: challenge.challenge,
      maxNumber: challenge.maxNumber,
      salt: challenge.salt,
      algorithm: challenge.algorithm,
      signature: challenge.signature,
      requiresCode,
      strength,
      codeChallenge,
    };
  }

  async validateChallenge(
    request: ValidationRequest,
  ): Promise<ValidationResponse> {
    this.log.debug(
      `Validating challenge for domain ${request.domain}, IP: ${request.ip}`,
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

    // The ALTCHA widget sends a Base64-encoded JSON payload
    // First, try to decode from Base64 (standard widget format)
    let payload: Payload;
    try {
      const decoded = Buffer.from(request.payload, 'base64').toString('utf-8');
      payload = JSON.parse(decoded) as Payload;
      this.log.debug('Decoded Base64 payload from widget');
    } catch (error) {
      // If Base64 decoding fails, try parsing as plain JSON (for API calls)
      try {
        payload = JSON.parse(request.payload) as Payload;
        this.log.debug('Parsed plain JSON payload');
      } catch {
        this.log.error(
          'Invalid payload format (neither Base64 nor JSON):',
          error,
        );
        return { verified: false };
      }
    }

    // CRITICAL: Fetch and delete atomically to prevent replay attacks
    // Using getChallengeDataAndDelete prevents race conditions where
    // the same solution could be validated multiple times simultaneously
    const challengeData = await this.redisService.getChallengeDataAndDelete(
      payload.challenge,
    );

    if (!challengeData) {
      this.log.warn(
        `Challenge data not found or already used for IP ${request.ip} on domain ${request.domain}`,
      );
      this.crowdSecService.reportFailedAttempt(request.ip, request.domain);
      this.metricsService.recordCaptchaValidated(
        request.domain,
        false,
        domainCfg.minStrength,
      );
      return { verified: false, reason: 'CHALLENGE_NOT_FOUND' };
    }

    const strength = challengeData.strength;
    const createdAt = challengeData.createdAt;

    // Verify the challenge was created for this IP and domain
    // Domain match can be either:
    // 1. Exact match (same domain key or origin)
    // 2. Both resolve to the same domain config
    let domainMatch = challengeData.domain === request.domain;
    if (!domainMatch) {
      // Check if both domains resolve to the same config
      let challengeDomainCfg = this.config.domain.getDomainConfig(
        challengeData.domain,
      );
      if (!challengeDomainCfg) {
        challengeDomainCfg = this.config.domain.findByOrigin(
          challengeData.domain,
        );
      }
      // domainCfg is already resolved from request.domain above
      domainMatch = challengeDomainCfg?.name === domainCfg.name;
    }

    if (!domainMatch) {
      this.log.warn(
        `Challenge domain mismatch: expected ${challengeData.domain}, got ${request.domain}`,
      );
      await this.redisService.updateIpStats(request.ip, request.domain, false);
      this.metricsService.recordCaptchaValidated(
        request.domain,
        false,
        challengeData.strength,
      );
      return { verified: false, reason: 'DOMAIN_MISMATCH' };
    }

    // Verify the solution
    const isValid = await verifySolution(payload, domainCfg.key);

    if (!isValid) {
      this.log.warn(
        `ALTCHA solution validation failed for IP ${request.ip} on domain ${request.domain}`,
      );
      // Report failed attempt to CrowdSec
      this.crowdSecService.reportFailedAttempt(request.ip, request.domain);
      // Update IP stats
      await this.redisService.updateIpStats(request.ip, request.domain, false);
      // Check if we should report to AbuseIPDB
      await this.checkAndReportToAbuseIPDB(
        request.ip,
        request.domain,
        'Invalid CAPTCHA solution attempt',
      );
      // Record metrics
      this.metricsService.recordCaptchaValidated(
        request.domain,
        false,
        strength,
        (Date.now() - createdAt) / 1000,
      );
      return { verified: false, reason: 'INVALID_SOLUTION' };
    }

    // Check for disposable email if enabled and email is present in data
    if (
      domainCfg.enableDisposableEmailCheck &&
      request.data &&
      request.data.email
    ) {
      const email = String(request.data.email).toLowerCase();
      const emailDomain = email.split('@')[1];

      if (emailDomain && disposableDomains.includes(emailDomain)) {
        this.log.warn(
          `Disposable email domain detected: ${emailDomain} for IP ${request.ip}`,
        );
        // Treat disposable email as validation failure
        this.crowdSecService.reportFailedAttempt(request.ip, request.domain);
        await this.redisService.updateIpStats(
          request.ip,
          request.domain,
          false,
        );
        // Check if we should report to AbuseIPDB
        await this.checkAndReportToAbuseIPDB(
          request.ip,
          request.domain,
          'Disposable email domain usage attempt',
        );
        this.metricsService.recordCaptchaValidated(
          request.domain,
          false,
          strength,
          (Date.now() - createdAt) / 1000,
        );
        return { verified: false, reason: 'DISPOSABLE_EMAIL' };
      }
    }

    // If verification code was required for this challenge, validate it
    if (
      domainCfg.codeVerificationIfStrengthGT >= 0 &&
      strength >= domainCfg.codeVerificationIfStrengthGT
    ) {
      if (!request.verificationCode) {
        this.log.warn(
          `Verification code missing for high-threat challenge (strength ${strength}) from IP ${request.ip}`,
        );
        this.crowdSecService.reportFailedAttempt(request.ip, request.domain);
        await this.redisService.updateIpStats(
          request.ip,
          request.domain,
          false,
        );
        this.metricsService.recordCaptchaValidated(
          request.domain,
          false,
          strength,
        );
        return { verified: false, reason: 'CODE_REQUIRED' };
      }

      // Get the stored verification code
      const codeData = await this.redisService.getVerificationCode(
        payload.challenge,
      );

      if (!codeData) {
        this.log.warn(
          `Verification code not found or expired for challenge from IP ${request.ip}`,
        );
        this.crowdSecService.reportFailedAttempt(request.ip, request.domain);
        await this.redisService.updateIpStats(
          request.ip,
          request.domain,
          false,
        );
        this.metricsService.recordCaptchaValidated(
          request.domain,
          false,
          strength,
        );
        return { verified: false, reason: 'CODE_EXPIRED' };
      }

      // Verify the code matches (case-insensitive)
      const codeValid =
        codeData.code.toLowerCase() === request.verificationCode.toLowerCase();

      if (!codeValid) {
        this.log.warn(
          `Verification code mismatch for IP ${request.ip} on domain ${request.domain}`,
        );
        this.crowdSecService.reportFailedAttempt(request.ip, request.domain);
        await this.redisService.updateIpStats(
          request.ip,
          request.domain,
          false,
        );
        // Check if we should report to AbuseIPDB
        await this.checkAndReportToAbuseIPDB(
          request.ip,
          request.domain,
          'Invalid verification code attempt',
        );
        this.metricsService.recordCaptchaValidated(
          request.domain,
          false,
          strength,
        );
        return { verified: false, reason: 'CODE_INVALID' };
      }

      this.log.debug(
        `Verification code validated successfully for IP ${request.ip}`,
      );
    }

    // Calculate solve time
    const solveTime = (Date.now() - createdAt) / 1000; // in seconds

    // Update IP stats
    await this.redisService.updateIpStats(request.ip, request.domain, true);

    // Record metrics
    this.metricsService.recordCaptchaValidated(
      request.domain,
      true,
      strength,
      solveTime,
    );

    // Challenge was already deleted atomically in getChallengeDataAndDelete
    // Delete the verification code as well if it exists
    if (
      domainCfg.codeVerificationIfStrengthGT >= 0 &&
      strength >= domainCfg.codeVerificationIfStrengthGT
    ) {
      await this.redisService.deleteVerificationCode(payload.challenge);
    }

    // Generate Sentinel verification token
    // CRITICAL: verificationData must include form data to prevent tampering
    // If we only sign the PoW payload, attackers can:
    // 1) Send valid PoW + good content to Sentinel
    // 2) Get valid signature
    // 3) Send signature + malicious content to backend
    const timestamp = Date.now();

    // Bundle payload and form data into verificationData
    // CRITICAL: Use canonical JSON to ensure consistent key ordering across different backends
    const verificationPayload = {
      payload: request.payload,
      fields: request.data || {},
    };
    const verificationData = stringify(verificationPayload);

    const signature = this.generateVerificationSignature(
      verificationData,
      timestamp,
      request.ip,
      request.domain,
      domainCfg.key,
      domainCfg.verifyIpAddress,
    );

    // Calculate spam score (0 = clean, higher = more suspicious)
    const score = Math.min(strength / 2, 50); // Normalize strength to 0-50 score

    this.log.debug(
      `Challenge validated successfully for IP ${request.ip} on domain ${request.domain}, solve time: ${solveTime}s`,
    );

    // Handle forward host if configured
    if (domainCfg.forwardHost) {
      this.log.debug(
        `Forwarding validated data to ${domainCfg.forwardHost} for domain ${request.domain}`,
      );

      try {
        const forwardData = {
          ...request.data,
          _altcha_verified: true,
          _altcha_verificationData: verificationData,
          _altcha_signature: signature,
          _altcha_time: timestamp,
        };

        const response = await fetch(domainCfg.forwardHost, {
          method: 'POST',
          headers: {
            'Content-Type': 'application/json',
          },
          body: JSON.stringify(forwardData),
        });

        if (!response.ok) {
          this.log.error(
            `Forward host returned error status: ${response.status}`,
          );
          throw new HttpException(
            'Forward host validation failed',
            HttpStatus.BAD_GATEWAY,
          );
        }

        const html = await response.text();
        this.log.debug(`Received HTML response from forward host`);

        return {
          verified: true,
          verificationData,
          signature,
          time: timestamp,
          algorithm: 'SHA-256',
          score, // Spam score for client/backend use
          fields: request.data, // Return validated fields to prevent tampering
          forwardedHtml: html,
        };
      } catch (error) {
        this.log.error(
          `Failed to forward to ${domainCfg.forwardHost}: ${error instanceof Error ? error.message : 'Unknown error'}`,
        );
        throw new HttpException(
          'Failed to forward request to configured host',
          HttpStatus.BAD_GATEWAY,
        );
      }
    }

    return {
      verified: true,
      verificationData,
      signature,
      time: timestamp,
      algorithm: 'SHA-256',
      score, // Spam score for client/backend use
      fields: request.data, // Return validated fields to prevent tampering
    };
  }

  /**
   * Verifies a Sentinel verification signature from a backend application
   * This allows stateless verification without Redis lookup
   *
   * IMPORTANT: The verificationData now contains both the PoW payload AND form fields.
   * Format: JSON.stringify({ payload: string, fields: Record<string, any> })
   *
   * This prevents tampering attacks where:
   * 1) Attacker sends valid PoW + good content to Sentinel
   * 2) Gets valid signature
   * 3) Tries to send signature + malicious content to backend
   *
   * The backend should:
   * 1) Parse verificationData to extract both payload and fields
   * 2) Verify the signature matches
   * 3) Use the fields from verificationData (not from request body) as source of truth
   */
  async verifyBackendSubmission(
    domain: string,
    verificationData: string,
    signature: string,
    time: number,
    ip?: string,
    maxAge: number = 300, // 5 minutes default
  ): Promise<boolean> {
    // Try to find domain by name first, then by origin
    let domainCfg = this.config.domain.getDomainConfig(domain);
    if (!domainCfg) {
      domainCfg = this.config.domain.findByOrigin(domain);
    }

    if (!domainCfg || !domainCfg.key) {
      this.log.warn(`Domain ${domain} not configured for verification`);
      return false;
    }

    // Check if signature has already been used (replay attack prevention)
    const isUsed = await this.redisService.isSignatureUsed(signature);
    if (isUsed) {
      this.log.warn(
        `Signature has already been used (replay attack attempt): ${signature.substring(0, 16)}...`,
      );
      return false;
    }

    // Check timestamp validity (prevent replay attacks)
    const age = (Date.now() - time) / 1000;
    if (age > maxAge || age < 0) {
      this.log.warn(
        `Verification signature expired or invalid timestamp (age: ${age}s)`,
      );
      return false;
    }

    // Verify signature
    // If IP is not provided, skip IP verification (use empty string)
    const verifyIpAddress = ip ? domainCfg.verifyIpAddress : false;
    const expectedSignature = this.generateVerificationSignature(
      verificationData,
      time,
      ip || '',
      domain,
      domainCfg.key,
      verifyIpAddress,
    );

    const isValid = signature === expectedSignature;

    if (isValid) {
      // Mark signature as used with TTL equal to maxAge
      await this.redisService.markSignatureAsUsed(signature, maxAge);
      this.log.debug(
        `Signature marked as used: ${signature.substring(0, 16)}...`,
      );
    }

    return isValid;
  }

  private generateVerificationSignature(
    verificationData: string,
    timestamp: number,
    ip: string,
    domain: string,
    key: string,
    verifyIpAddress: boolean = true,
  ): string {
    // Create HMAC signature binding the verification to domain and timestamp
    // Optionally bind to IP address based on configuration
    const data = verifyIpAddress
      ? `${verificationData}:${timestamp}:${ip}:${domain}`
      : `${verificationData}:${timestamp}:${domain}`;
    const hmac = createHmac('sha256', key);
    hmac.update(data);
    return hmac.digest('hex');
  }

  private generateRandomCode(length: number): string {
    const chars = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789';
    let code = '';
    const bytes = randomBytes(length);
    for (let i = 0; i < length; i++) {
      code += chars[bytes[i] % chars.length];
    }
    return code;
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

  /**
   * Check if an IP should be reported to AbuseIPDB based on failure threshold.
   * Reports if the number of failures exceeds the configured threshold.
   */
  private async checkAndReportToAbuseIPDB(
    ip: string,
    domain: string,
    comment: string,
  ): Promise<void> {
    // Check if AbuseIPDB reporting is enabled
    if (!this.config.abuseipdb.reportEnabled) {
      return;
    }

    // Get IP stats to check failure count
    const ipStats = await this.redisService.getIpStats(ip, domain);

    // Report if failures exceed threshold
    if (ipStats.failures >= this.config.abuseipdb.reportThreshold) {
      this.log.debug(
        `IP ${ip} has ${ipStats.failures} failures, reporting to AbuseIPDB`,
      );

      // AbuseIPDB category codes:
      // 21 = Brute Force
      // 18 = Web Spam
      const categories = [21, 18];
      const fullComment = `[automated] ${comment} on domain ${domain} (${ipStats.failures} failures, ${ipStats.attempts} attempts)`;

      await this.abuseIPDBService.reportIP(ip, categories, fullComment);
    }
  }
}
