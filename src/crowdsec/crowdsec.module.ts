import { Module } from '@nestjs/common';
import { CrowdSecService } from './crowdsec.service';

@Module({
  providers: [CrowdSecService],
  exports: [CrowdSecService],
})
export class CrowdSecModule {}
