import { Injectable } from '@nestjs/common';
import { $bool, $range, $str } from '@scolastico-dev/env-helper';
import { RedisConfigService } from './redis.config';
import { OtlpConfigService } from './otlp.config';
import { CrowdSecConfigService } from './crowdsec.config';
import { DomainConfigService } from './domain.config';
import { AbuseIPDBConfigService } from './abuseipdb.config';
import { SpamhausConfigService } from './spamhaus.config';

import dotenv from 'dotenv';
dotenv.config();

@Injectable()
export class BaseConfigService {
  /** @hidden */
  constructor() {}

  /** @hidden */
  redis = new RedisConfigService();

  /** @hidden */
  otlp = new OtlpConfigService();

  /** @hidden */
  crowdsec = new CrowdSecConfigService();

  /** @hidden */
  domain = new DomainConfigService();

  /** @hidden */
  abuseipdb = new AbuseIPDBConfigService();

  /** @hidden */
  spamhaus = new SpamhausConfigService();

  /**
   * The port on which the server will run.
   * @env PORT
   * @default 3000
   * @example PORT=3000
   */
  readonly port = $range('PORT', 1, 65535, 3000);

  /**
   * The ip header to trust for client IP extraction, if not provided directly.
   * @env TRUSTED_IP_HEADER
   * @default ''
   * @example TRUSTED_IP_HEADER=X-Forwarded-For
   */
  readonly trustedIpHeader = $str('TRUSTED_IP_HEADER', '');

  /**
   * Number of bits to strip from IPv6 addresses for privacy/rate limiting.
   * Default is 64, which strips the last 64 bits (interface identifier).
   * Set to 0 to disable IPv6 stripping.
   * @env IPV6_STRIP_BITS
   * @default 64
   * @example IPV6_STRIP_BITS=64
   */
  readonly ipv6StripBits = $range('IPV6_STRIP_BITS', 0, 128, 64);

  /**
   * Enable demo endpoints.
   * /demo serves a demo HTML page.
   * /ip shows detected client IP address for verification.
   * @env DEMO_ENABLED
   * @default false
   * @example DEMO_ENABLED=true
   */
  readonly demoEnabled = $bool('DEMO_ENABLED', false);
}
