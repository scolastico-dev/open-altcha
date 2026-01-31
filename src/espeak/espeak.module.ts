import { Module } from '@nestjs/common';
import { EspeakController } from './espeak.controller';
import { EspeakService } from './espeak.service';
import { RedisModule } from '../redis/redis.module';

@Module({
  imports: [RedisModule],
  controllers: [EspeakController],
  providers: [EspeakService],
  exports: [EspeakService],
})
export class EspeakModule {}
