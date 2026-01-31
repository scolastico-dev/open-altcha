import { Global, Module } from '@nestjs/common';
import { BaseConfigService } from './base.config';

@Global()
@Module({
  providers: [BaseConfigService],
  exports: [BaseConfigService],
})
export class ConfigModule {}
