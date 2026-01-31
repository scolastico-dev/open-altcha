import { Module } from '@nestjs/common';
import { SpamhausService } from './spamhaus.service';
import { RedisModule } from 'src/redis/redis.module';

@Module({
  imports: [RedisModule],
  providers: [SpamhausService],
  exports: [SpamhausService],
})
export class SpamhausModule {}
