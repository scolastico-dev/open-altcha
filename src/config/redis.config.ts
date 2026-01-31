import {
  $bool,
  $min,
  $str,
  $urlWithoutTrailingSlash,
} from '@scolastico-dev/env-helper';

export class RedisConfigService {
  /** @hidden */
  constructor() {}

  /**
   * Indicates whether Redis should be used for caching.
   * @env REDIS_ENABLED
   * @default false
   * @example REDIS_ENABLED=true
   */
  readonly enabled = $bool('REDIS_ENABLED', false);

  /**
   * The Redis connection URL.
   * @env REDIS_URL
   * @default redis://localhost:6379
   * @example REDIS_URL=redis://localhost:6379
   */
  readonly url = $urlWithoutTrailingSlash(
    'REDIS_URL',
    'redis://localhost:6379',
  );

  /**
   * Redis key prefix for ALTCHA data.
   * @env REDIS_PREFIX
   * @default altcha:
   * @example REDIS_PREFIX=altcha:
   */
  readonly prefix = $str('REDIS_PREFIX', 'altcha:');

  /**
   * TTL for challenge data in seconds.
   * @env REDIS_CHALLENGE_TTL
   * @default 300
   * @example REDIS_CHALLENGE_TTL=300
   */
  readonly challengeTtl = $min('REDIS_CHALLENGE_TTL', 1, 300);
}
