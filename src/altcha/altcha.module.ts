import { Module } from '@nestjs/common';
import { ChallengeService } from './challenge.service';
import { ValidationService } from './validation.service';
import { ChallengeController } from './challenge.controller';
import { ValidationController } from './validation.controller';
import { RedisModule } from '../redis/redis.module';
import { CrowdSecModule } from '../crowdsec/crowdsec.module';
import { AbuseIPDBModule } from '../abuseipdb/abuseipdb.module';
import { SpamhausModule } from '../spamhaus/spamhaus.module';
import { IpService } from './ip.service';

@Module({
  imports: [RedisModule, CrowdSecModule, AbuseIPDBModule, SpamhausModule],
  controllers: [ChallengeController, ValidationController],
  providers: [ChallengeService, ValidationService, IpService],
  exports: [IpService],
})
export class AltchaModule {}
