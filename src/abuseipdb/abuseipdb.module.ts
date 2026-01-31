import { Module } from '@nestjs/common';
import { AbuseIPDBService } from './abuseipdb.service';
import { RedisModule } from 'src/redis/redis.module';

@Module({
  imports: [RedisModule],
  providers: [AbuseIPDBService],
  exports: [AbuseIPDBService],
})
export class AbuseIPDBModule {}
