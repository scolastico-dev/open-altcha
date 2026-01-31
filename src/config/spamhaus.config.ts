import { $bool, $min, $range } from '@scolastico-dev/env-helper';

export class SpamhausConfigService {
  /** @hidden */
  constructor() {}

  /**
   * Whether Spamhaus DNSBL checking is enabled globally.
   * @env SPAMHAUS_ENABLED
   * @default false
   * @example SPAMHAUS_ENABLED=true
   */
  readonly enabled = $bool('SPAMHAUS_ENABLED', false);

  /**
   * Strength increase when IP is found in Spamhaus.
   * @env SPAMHAUS_STRENGTH_INCREASE
   * @default 50
   * @example SPAMHAUS_STRENGTH_INCREASE=50
   */
  readonly strengthIncrease = $range(
    'SPAMHAUS_STRENGTH_INCREASE',
    0,
    Number.MAX_SAFE_INTEGER,
    50,
  );

  /**
   * DNS lookup timeout in milliseconds.
   * @env SPAMHAUS_TIMEOUT_MS
   * @default 3000
   * @example SPAMHAUS_TIMEOUT_MS=3000
   */
  readonly timeoutMs = $range('SPAMHAUS_TIMEOUT_MS', 500, 10000, 3000);

  /**
   * Cache TTL for IP check results in seconds.
   * Caching reduces DNS lookups and improves performance.
   * @env SPAMHAUS_CACHE_TTL
   * @default 3600
   * @example SPAMHAUS_CACHE_TTL=3600
   */
  readonly cacheTtl = $min('SPAMHAUS_CACHE_TTL', 60, 3600);
}
