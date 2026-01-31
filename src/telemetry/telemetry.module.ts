import { Global, Module } from '@nestjs/common';
import { OtlpService } from './otlp.service';
import { MetricsService } from './metrics.service';

@Global()
@Module({
  providers: [OtlpService, MetricsService],
  exports: [OtlpService, MetricsService],
})
export class TelemetryModule {}
