import {
  Injectable,
  OnModuleInit,
  OnModuleDestroy,
  Logger,
} from '@nestjs/common';
import { NodeSDK } from '@opentelemetry/sdk-node';
import { getNodeAutoInstrumentations } from '@opentelemetry/auto-instrumentations-node';
import { OTLPTraceExporter } from '@opentelemetry/exporter-trace-otlp-http';
import { OTLPMetricExporter } from '@opentelemetry/exporter-metrics-otlp-http';
import { resourceFromAttributes } from '@opentelemetry/resources';
import { ATTR_SERVICE_NAME } from '@opentelemetry/semantic-conventions';
import { PeriodicExportingMetricReader } from '@opentelemetry/sdk-metrics';
import { BaseConfigService } from '../config';

@Injectable()
export class OtlpService implements OnModuleInit, OnModuleDestroy {
  private readonly log = new Logger(OtlpService.name);
  private sdk: NodeSDK | null = null;

  constructor(private readonly config: BaseConfigService) {}

  onModuleInit() {
    this.initializeOTLP();
  }

  async onModuleDestroy() {
    if (this.sdk) {
      this.log.log('Shutting down OTLP...');
      await this.sdk.shutdown();
    }
  }

  private initializeOTLP() {
    const otlpConfig = this.config.otlp;

    if (!otlpConfig.enabled) {
      this.log.warn('OTLP tracing is disabled');
      return;
    }

    const resource = resourceFromAttributes({
      [ATTR_SERVICE_NAME]: otlpConfig.serviceName,
    });

    const traceExporter = new OTLPTraceExporter({
      url: otlpConfig.traceEndpoint,
    });

    const metricExporter = new OTLPMetricExporter({
      url: otlpConfig.metricsEndpoint,
    });

    const metricReader = new PeriodicExportingMetricReader({
      exporter: metricExporter,
      exportIntervalMillis: 60000, // Export every 60 seconds
    });

    this.sdk = new NodeSDK({
      resource,
      traceExporter,
      metricReader,
      instrumentations: [getNodeAutoInstrumentations()],
    });

    try {
      this.sdk.start();
      this.log.log('OTLP tracing initialized successfully');
    } catch (error) {
      this.log.error('Error initializing OTLP:', error);
      this.sdk = null;
    }
  }
}
