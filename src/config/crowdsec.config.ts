import {
  $bool,
  $min,
  $str,
  $urlWithoutTrailingSlash,
} from '@scolastico-dev/env-helper';

export class CrowdSecConfigService {
  /** @hidden */
  constructor() {}

  /**
   * Indicates whether CrowdSec integration is enabled.
   * @env CROWDSEC_ENABLED
   * @default false
   * @example CROWDSEC_ENABLED=true
   */
  readonly enabled = $bool('CROWDSEC_ENABLED', false);

  /**
   * The CrowdSec LAPI URL.
   * @env CROWDSEC_LAPI_URL
   * @default http://localhost:8080
   * @example CROWDSEC_LAPI_URL=http://localhost:8080
   */
  readonly lapiUrl = $urlWithoutTrailingSlash(
    'CROWDSEC_LAPI_URL',
    'http://localhost:8080',
  );

  /**
   * The CrowdSec API key.
   * @env CROWDSEC_API_KEY
   * @default ''
   * @example CROWDSEC_API_KEY=your-api-key
   */
  readonly apiKey = $str('CROWDSEC_API_KEY', '');

  /**
   * Minimum strength increase for suspicious IPs.
   * @env CROWDSEC_MIN_STRENGTH_INCREASE
   * @default 20
   * @example CROWDSEC_MIN_STRENGTH_INCREASE=20
   */
  readonly minStrengthIncrease = $min('CROWDSEC_MIN_STRENGTH_INCREASE', 1, 20);

  /**
   * Maximum strength increase for known attackers.
   * @env CROWDSEC_MAX_STRENGTH_INCREASE
   * @default 50
   * @example CROWDSEC_MAX_STRENGTH_INCREASE=50
   */
  readonly maxStrengthIncrease = $min('CROWDSEC_MAX_STRENGTH_INCREASE', 1, 50);

  /**
   * Fail-open strategy: if true, allow requests when CrowdSec is unreachable.
   * If false, reject requests when CrowdSec fails.
   * @env CROWDSEC_FAIL_OPEN
   * @default true
   * @example CROWDSEC_FAIL_OPEN=true
   */
  readonly failOpen = $bool('CROWDSEC_FAIL_OPEN', true);
}
