import { $bool, $list, $range, $str } from '@scolastico-dev/env-helper';

export interface DomainConfig {
  name: string;
  origins: string[];
  key: string;
  minStrength: number;
  maxStrength: number;
  codeVerificationIfStrengthGT: number;
  codeVerificationLength: number;
  challengeExpiresSeconds: number;
  verifyIpAddress: boolean;
  forwardHost?: string;
  challengeRequestPenalty: number;
  highFailureRateThreshold: number;
  highFailureRateIncrease: number;
  mediumFailureRateThreshold: number;
  mediumFailureRateIncrease: number;
  manyAttemptsThreshold: number;
  manyAttemptsIncrease: number;
  // New security options
  enableAbuseIPDB: boolean;
  enableSpamhaus: boolean;
  enableDisposableEmailCheck: boolean;
}

export class DomainConfigService {
  /** @hidden */
  constructor() {}

  /**
   * The challenge response scaling factor.
   * If the server decides for a captcha strength of 50, and the scaling factor is 100000,
   * the final strength will be 50 * 100,000 = 5,000,000.
   * @env CHALLENGE_RESPONSE_SCALING_FACTOR
   * @default 100000
   * @example CHALLENGE_RESPONSE_SCALING_FACTOR=100000
   */
  readonly challengeResponseScalingFactor = $range(
    'CHALLENGE_RESPONSE_SCALING_FACTOR',
    1,
    1_000_000,
    100_000,
  );

  /**
   * Comma-separated list of domain identifiers.
   * For each domain in the list, the following environment variables can be configured:
   *
   * Required:
   * - DOMAIN_<NAME>_ORIGINS: Comma-separated list of allowed origins
   * - DOMAIN_<NAME>_KEY: Secret key for the domain
   *
   * Optional (with defaults):
   * - DOMAIN_<NAME>_MIN_STRENGTH: Minimum challenge strength (0 to Number.MAX_SAFE_INTEGER, default: 10)
   * - DOMAIN_<NAME>_MAX_STRENGTH: Maximum challenge strength (0 to Number.MAX_SAFE_INTEGER, default: 90)
   * - DOMAIN_<NAME>_CODE_VERIFICATION_IF_STRENGTH_GT: Enable code verification if strength greater than (-1 to 100, default: 70)
   * - DOMAIN_<NAME>_CODE_VERIFICATION_LENGTH: Length of verification code (4 to 10, default: 6)
   * - DOMAIN_<NAME>_CHALLENGE_EXPIRES_SECONDS: Challenge expiration time in seconds (60 to 3600, default: 300)
   * - DOMAIN_<NAME>_VERIFY_IP_ADDRESS: Whether to verify IP address (boolean, default: true)
   * - DOMAIN_<NAME>_FORWARD_HOST: Host to forward requests to (optional)
   * - DOMAIN_<NAME>_CHALLENGE_REQUEST_PENALTY: Penalty points for challenge requests (0 to Number.MAX_SAFE_INTEGER, default: 5)
   * - DOMAIN_<NAME>_HIGH_FAILURE_RATE_THRESHOLD: Threshold for high failure rate (0 to 1, default: 0.5)
   * - DOMAIN_<NAME>_HIGH_FAILURE_RATE_INCREASE: Strength increase for high failure rate (0 to Number.MAX_SAFE_INTEGER, default: 30)
   * - DOMAIN_<NAME>_MEDIUM_FAILURE_RATE_THRESHOLD: Threshold for medium failure rate (0 to 1, default: 0.3)
   * - DOMAIN_<NAME>_MEDIUM_FAILURE_RATE_INCREASE: Strength increase for medium failure rate (0 to Number.MAX_SAFE_INTEGER, default: 15)
   * - DOMAIN_<NAME>_MANY_ATTEMPTS_THRESHOLD: Threshold for many attempts (0 to Number.MAX_SAFE_INTEGER, default: 10)
   * - DOMAIN_<NAME>_MANY_ATTEMPTS_INCREASE: Strength increase for many attempts (0 to Number.MAX_SAFE_INTEGER, default: 10)
   * - DOMAIN_<NAME>_ENABLE_ABUSEIPDB: Enable AbuseIPDB checking for this domain (boolean, default: false)
   * - DOMAIN_<NAME>_ENABLE_SPAMHAUS: Enable Spamhaus checking for this domain (boolean, default: false)
   * - DOMAIN_<NAME>_ENABLE_DISPOSABLE_EMAIL_CHECK: Enable disposable email checking for this domain (boolean, default: false)
   *
   * @example
   * DOMAIN_LIST=example,test
   * DOMAIN_EXAMPLE_ORIGINS=https://example.com,https://www.example.com
   * DOMAIN_EXAMPLE_KEY=your-secret-key
   * DOMAIN_EXAMPLE_MIN_STRENGTH=20
   * DOMAIN_EXAMPLE_MAX_STRENGTH=80
   * DOMAIN_EXAMPLE_ENABLE_ABUSEIPDB=true
   * DOMAIN_EXAMPLE_ENABLE_SPAMHAUS=true
   * DOMAIN_EXAMPLE_ENABLE_DISPOSABLE_EMAIL_CHECK=true
   */
  private readonly domainList = $list('DOMAIN_LIST');

  /** @hidden */
  getDomains(): DomainConfig[] {
    return this.domainList.map((name: string) => this.parseDomainConfig(name));
  }

  /** @hidden */
  getDomainConfig(domainName: string): DomainConfig | undefined {
    const domains = this.getDomains();
    return domains.find((d) => d.name === domainName);
  }

  /** @hidden */
  findByOrigin(origin: string): DomainConfig | undefined {
    const domains = this.getDomains();
    return domains.find((d) => d.origins.includes(origin));
  }

  /** @hidden */
  private parseDomainConfig(name: string): DomainConfig {
    const upperName = name.toUpperCase();

    const origins = $list(`DOMAIN_${upperName}_ORIGINS`) as string[];
    const key = $str(`DOMAIN_${upperName}_KEY`);
    const minStrength = $range(
      `DOMAIN_${upperName}_MIN_STRENGTH`,
      0,
      Number.MAX_SAFE_INTEGER,
      10,
    );
    const maxStrength = $range(
      `DOMAIN_${upperName}_MAX_STRENGTH`,
      0,
      Number.MAX_SAFE_INTEGER,
      90,
    );
    if (minStrength > maxStrength)
      throw new Error(
        `DOMAIN_${upperName}_MIN_STRENGTH cannot be greater than DOMAIN_${upperName}_MAX_STRENGTH`,
      );

    const codeVerificationLength = $range(
      `DOMAIN_${upperName}_CODE_VERIFICATION_LENGTH`,
      4,
      10,
      6,
    );
    const codeVerificationIfStrengthGT = $range(
      `DOMAIN_${upperName}_CODE_VERIFICATION_IF_STRENGTH_GT`,
      -1,
      100,
      70,
    );
    const challengeExpiresSeconds = $range(
      `DOMAIN_${upperName}_CHALLENGE_EXPIRES_SECONDS`,
      60,
      3600,
      300,
    );
    const verifyIpAddress = $bool(
      `DOMAIN_${upperName}_VERIFY_IP_ADDRESS`,
      true,
    );
    const forwardHost = $str(`DOMAIN_${upperName}_FORWARD_HOST`, '');
    const challengeRequestPenalty = $range(
      `DOMAIN_${upperName}_CHALLENGE_REQUEST_PENALTY`,
      0,
      Number.MAX_SAFE_INTEGER,
      5,
    );
    const highFailureRateThreshold = $range(
      `DOMAIN_${upperName}_HIGH_FAILURE_RATE_THRESHOLD`,
      0,
      1,
      0.5,
    );
    const highFailureRateIncrease = $range(
      `DOMAIN_${upperName}_HIGH_FAILURE_RATE_INCREASE`,
      0,
      Number.MAX_SAFE_INTEGER,
      30,
    );
    const mediumFailureRateThreshold = $range(
      `DOMAIN_${upperName}_MEDIUM_FAILURE_RATE_THRESHOLD`,
      0,
      1,
      0.3,
    );
    const mediumFailureRateIncrease = $range(
      `DOMAIN_${upperName}_MEDIUM_FAILURE_RATE_INCREASE`,
      0,
      Number.MAX_SAFE_INTEGER,
      15,
    );
    const manyAttemptsIncrease = $range(
      `DOMAIN_${upperName}_MANY_ATTEMPTS_INCREASE`,
      0,
      Number.MAX_SAFE_INTEGER,
      10,
    );
    const manyAttemptsThreshold = $range(
      `DOMAIN_${upperName}_MANY_ATTEMPTS_THRESHOLD`,
      0,
      Number.MAX_SAFE_INTEGER,
      10,
    );
    const enableAbuseIPDB = $bool(
      `DOMAIN_${upperName}_ENABLE_ABUSEIPDB`,
      false,
    );
    const enableSpamhaus = $bool(`DOMAIN_${upperName}_ENABLE_SPAMHAUS`, false);
    const enableDisposableEmailCheck = $bool(
      `DOMAIN_${upperName}_ENABLE_DISPOSABLE_EMAIL_CHECK`,
      false,
    );

    return {
      name,
      origins,
      key,
      minStrength,
      maxStrength,
      codeVerificationIfStrengthGT,
      codeVerificationLength,
      challengeExpiresSeconds,
      verifyIpAddress,
      forwardHost: forwardHost || undefined,
      challengeRequestPenalty,
      highFailureRateThreshold,
      highFailureRateIncrease,
      mediumFailureRateThreshold,
      mediumFailureRateIncrease,
      manyAttemptsThreshold,
      manyAttemptsIncrease,
      enableAbuseIPDB,
      enableSpamhaus,
      enableDisposableEmailCheck,
    };
  }
}
