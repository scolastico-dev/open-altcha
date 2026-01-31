import { $bool, $min, $range, $str } from '@scolastico-dev/env-helper';

export class AbuseIPDBConfigService {
  /** @hidden */
  constructor() {}

  /**
   * Whether AbuseIPDB IP checking is enabled.
   * This controls IP reputation checks via the AbuseIPDB API.
   * Can be enabled independently from reporting.
   * @env ABUSEIPDB_CHECK_ENABLED
   * @default false
   * @example ABUSEIPDB_CHECK_ENABLED=true
   */
  readonly checkEnabled = $bool('ABUSEIPDB_CHECK_ENABLED', false);

  /**
   * AbuseIPDB API key.
   * Required if AbuseIPDB checking is enabled.
   * @env ABUSEIPDB_API_KEY
   * @default ''
   * @example ABUSEIPDB_API_KEY=your-api-key-here
   */
  readonly apiKey = $str('ABUSEIPDB_API_KEY', '');

  /**
   * Maximum age in days to check AbuseIPDB reports.
   * @env ABUSEIPDB_MAX_AGE_DAYS
   * @default 90
   * @example ABUSEIPDB_MAX_AGE_DAYS=90
   */
  readonly maxAgeDays = $range('ABUSEIPDB_MAX_AGE_DAYS', 1, 365, 90);

  /**
   * Confidence threshold (0-100) to consider IP as malicious.
   * @env ABUSEIPDB_CONFIDENCE_THRESHOLD
   * @default 75
   * @example ABUSEIPDB_CONFIDENCE_THRESHOLD=75
   */
  readonly confidenceThreshold = $range(
    'ABUSEIPDB_CONFIDENCE_THRESHOLD',
    0,
    100,
    75,
  );

  /**
   * Strength increase when IP is found in AbuseIPDB.
   * @env ABUSEIPDB_STRENGTH_INCREASE
   * @default 40
   * @example ABUSEIPDB_STRENGTH_INCREASE=40
   */
  readonly strengthIncrease = $range(
    'ABUSEIPDB_STRENGTH_INCREASE',
    0,
    Number.MAX_SAFE_INTEGER,
    40,
  );

  /**
   * Whether to report failed validation attempts to AbuseIPDB.
   * This controls reporting of malicious IPs to AbuseIPDB.
   * Can be enabled independently from checking.
   * @env ABUSEIPDB_REPORT_ENABLED
   * @default false
   * @example ABUSEIPDB_REPORT_ENABLED=true
   */
  readonly reportEnabled = $bool('ABUSEIPDB_REPORT_ENABLED', false);

  /**
   * Minimum number of failed attempts before reporting to AbuseIPDB.
   * @env ABUSEIPDB_REPORT_THRESHOLD
   * @default 5
   * @example ABUSEIPDB_REPORT_THRESHOLD=5
   */
  readonly reportThreshold = $range('ABUSEIPDB_REPORT_THRESHOLD', 1, 1000, 5);

  /**
   * Cache TTL for IP check results in seconds.
   * Caching reduces API calls and improves performance.
   * @env ABUSEIPDB_CACHE_TTL
   * @default 3600
   * @example ABUSEIPDB_CACHE_TTL=3600
   */
  readonly cacheTtl = $min('ABUSEIPDB_CACHE_TTL', 60, 3600);
}
