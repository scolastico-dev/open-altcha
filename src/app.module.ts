import { Module } from '@nestjs/common';
import { AltchaModule } from './altcha/altcha.module';
import { RedisModule } from './redis/redis.module';
import { CrowdSecModule } from './crowdsec/crowdsec.module';
import { AppController } from './app.controller';
import { ConfigModule } from './config/config.module';
import { TelemetryModule } from './telemetry/telemetry.module';
import { AbuseIPDBModule } from './abuseipdb/abuseipdb.module';
import { SpamhausModule } from './spamhaus/spamhaus.module';
import { EspeakModule } from './espeak/espeak.module';

@Module({
  imports: [
    ConfigModule,
    AltchaModule,
    RedisModule,
    CrowdSecModule,
    TelemetryModule,
    AbuseIPDBModule,
    SpamhausModule,
    EspeakModule,
  ],
  controllers: [AppController],
  providers: [],
})
export class AppModule {}
