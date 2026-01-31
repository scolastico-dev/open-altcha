import {
  $bool,
  $str,
  $urlWithoutTrailingSlash,
} from '@scolastico-dev/env-helper';

export class OtlpConfigService {
  /** @hidden */
  constructor() {}

  /**
   * Indicates whether OTLP tracing is enabled.
   * @env OTLP_ENABLED
   * @default true
   * @example OTLP_ENABLED=true
   */
  readonly enabled = $bool('OTLP_ENABLED', true);

  /**
   * The OTLP exporter endpoint for traces.
   * @env OTLP_TRACE_ENDPOINT
   * @default http://localhost:4318/v1/traces
   * @example OTLP_TRACE_ENDPOINT=http://localhost:4318/v1/traces
   */
  readonly traceEndpoint = $urlWithoutTrailingSlash(
    'OTLP_TRACE_ENDPOINT',
    'http://localhost:4318/v1/traces',
  );

  /**
   * The OTLP exporter endpoint for metrics.
   * @env OTLP_METRICS_ENDPOINT
   * @default http://localhost:4318/v1/metrics
   * @example OTLP_METRICS_ENDPOINT=http://localhost:4318/v1/metrics
   */
  readonly metricsEndpoint = $urlWithoutTrailingSlash(
    'OTLP_METRICS_ENDPOINT',
    'http://localhost:4318/v1/metrics',
  );

  /**
   * Service name for OTLP.
   * @env OTLP_SERVICE_NAME
   * @default altcha-server
   * @example OTLP_SERVICE_NAME=altcha-server
   */
  readonly serviceName = $str('OTLP_SERVICE_NAME', 'altcha-server');
}
