import { $bool, $list, $range, $str } from '@scolastico-dev/env-helper';

export interface DomainConfig {
  /**
   * The domain identifier name.
   */
  name: string;

  /**
   * Comma-separated list of allowed origins for this domain.
   * @env DOMAIN_<NAME>_ORIGINS
   * @example DOMAIN_EXAMPLE_ORIGINS=https://example.com,https://www.example.com
   */
  origins: string[];

  /**
   * Secret key for the domain.
   * @env DOMAIN_<NAME>_KEY
   * @example DOMAIN_EXAMPLE_KEY=your-secret-key
   */
  key: string;

  /**
   * Minimum challenge strength (0 to Number.MAX_SAFE_INTEGER).
   * @env DOMAIN_<NAME>_MIN_STRENGTH
   * @default 10
   * @example DOMAIN_EXAMPLE_MIN_STRENGTH=20
   */
  minStrength: number;

  /**
   * Maximum challenge strength (0 to Number.MAX_SAFE_INTEGER).
   * @env DOMAIN_<NAME>_MAX_STRENGTH
   * @default 90
   * @example DOMAIN_EXAMPLE_MAX_STRENGTH=80
   */
  maxStrength: number;

  /**
   * Enable code verification if strength is greater than this value (-1 to 100).
   * @env DOMAIN_<NAME>_CODE_VERIFICATION_IF_STRENGTH_GT
   * @default 70
   * @example DOMAIN_EXAMPLE_CODE_VERIFICATION_IF_STRENGTH_GT=70
   */
  codeVerificationIfStrengthGT: number;

  /**
   * Length of verification code (4 to 10).
   * @env DOMAIN_<NAME>_CODE_VERIFICATION_LENGTH
   * @default 6
   * @example DOMAIN_EXAMPLE_CODE_VERIFICATION_LENGTH=6
   */
  codeVerificationLength: number;

  /**
   * Challenge expiration time in seconds (60 to 3600).
   * @env DOMAIN_<NAME>_CHALLENGE_EXPIRES_SECONDS
   * @default 300
   * @example DOMAIN_EXAMPLE_CHALLENGE_EXPIRES_SECONDS=300
   */
  challengeExpiresSeconds: number;

  /**
   * Whether to verify IP address.
   * @env DOMAIN_<NAME>_VERIFY_IP_ADDRESS
   * @default true
   * @example DOMAIN_EXAMPLE_VERIFY_IP_ADDRESS=true
   */
  verifyIpAddress: boolean;

  /**
   * Host to forward requests to (optional).
   * @env DOMAIN_<NAME>_FORWARD_HOST
   * @example DOMAIN_EXAMPLE_FORWARD_HOST=https://api.example.com
   */
  forwardHost?: string;

  /**
   * Penalty points for challenge requests (0 to Number.MAX_SAFE_INTEGER).
   * @env DOMAIN_<NAME>_CHALLENGE_REQUEST_PENALTY
   * @default 5
   * @example DOMAIN_EXAMPLE_CHALLENGE_REQUEST_PENALTY=5
   */
  challengeRequestPenalty: number;

  /**
   * Threshold for high failure rate (0 to 1).
   * @env DOMAIN_<NAME>_HIGH_FAILURE_RATE_THRESHOLD
   * @default 0.5
   * @example DOMAIN_EXAMPLE_HIGH_FAILURE_RATE_THRESHOLD=0.5
   */
  highFailureRateThreshold: number;

  /**
   * Strength increase for high failure rate (0 to Number.MAX_SAFE_INTEGER).
   * @env DOMAIN_<NAME>_HIGH_FAILURE_RATE_INCREASE
   * @default 30
   * @example DOMAIN_EXAMPLE_HIGH_FAILURE_RATE_INCREASE=30
   */
  highFailureRateIncrease: number;

  /**
   * Threshold for medium failure rate (0 to 1).
   * @env DOMAIN_<NAME>_MEDIUM_FAILURE_RATE_THRESHOLD
   * @default 0.3
   * @example DOMAIN_EXAMPLE_MEDIUM_FAILURE_RATE_THRESHOLD=0.3
   */
  mediumFailureRateThreshold: number;

  /**
   * Strength increase for medium failure rate (0 to Number.MAX_SAFE_INTEGER).
   * @env DOMAIN_<NAME>_MEDIUM_FAILURE_RATE_INCREASE
   * @default 15
   * @example DOMAIN_EXAMPLE_MEDIUM_FAILURE_RATE_INCREASE=15
   */
  mediumFailureRateIncrease: number;

  /**
   * Threshold for many attempts (0 to Number.MAX_SAFE_INTEGER).
   * @env DOMAIN_<NAME>_MANY_ATTEMPTS_THRESHOLD
   * @default 10
   * @example DOMAIN_EXAMPLE_MANY_ATTEMPTS_THRESHOLD=10
   */
  manyAttemptsThreshold: number;

  /**
   * Strength increase for many attempts (0 to Number.MAX_SAFE_INTEGER).
   * @env DOMAIN_<NAME>_MANY_ATTEMPTS_INCREASE
   * @default 10
   * @example DOMAIN_EXAMPLE_MANY_ATTEMPTS_INCREASE=10
   */
  manyAttemptsIncrease: number;

  /**
   * Enable AbuseIPDB checking for this domain.
   * @env DOMAIN_<NAME>_ENABLE_ABUSEIPDB
   * @default false
   * @example DOMAIN_EXAMPLE_ENABLE_ABUSEIPDB=true
   */
  enableAbuseIPDB: boolean;

  /**
   * Enable Spamhaus checking for this domain.
   * @env DOMAIN_<NAME>_ENABLE_SPAMHAUS
   * @default false
   * @example DOMAIN_EXAMPLE_ENABLE_SPAMHAUS=true
   */
  enableSpamhaus: boolean;

  /**
   * Enable disposable email checking for this domain.
   * @env DOMAIN_<NAME>_ENABLE_DISPOSABLE_EMAIL_CHECK
   * @default false
   * @example DOMAIN_EXAMPLE_ENABLE_DISPOSABLE_EMAIL_CHECK=true
   */
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
   * Each domain is configured via environment variables prefixed with DOMAIN_<NAME>_.
   * See DomainConfig interface for available configuration options.
   * @env DOMAIN_LIST
   * @example DOMAIN_LIST=example,test
   */
  readonly domainList = $list('DOMAIN_LIST');

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
