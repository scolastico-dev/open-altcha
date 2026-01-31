import {
  Controller,
  Get,
  Res,
  Req,
  HttpException,
  HttpStatus,
} from '@nestjs/common';
import {
  ApiTags,
  ApiOperation,
  ApiResponse,
  ApiExcludeEndpoint,
} from '@nestjs/swagger';
import type { Response, Request } from 'express';
import { existsSync, readFileSync } from 'fs';
import { BaseConfigService } from './config/base.config';
import { IpService } from './altcha/ip.service';

@ApiTags('system')
@Controller()
export class AppController {
  constructor(
    private readonly config: BaseConfigService,
    private readonly ipService: IpService,
  ) {}

  @Get('health')
  @ApiOperation({
    summary: 'Health check',
    description: 'Returns the health status of the service',
  })
  @ApiResponse({
    status: 200,
    description: 'Service is healthy',
  })
  health() {
    return {
      status: 'ok',
      timestamp: new Date().toISOString(),
    };
  }

  @Get()
  @ApiExcludeEndpoint()
  root(@Res() res: Response) {
    res.redirect('/swagger');
  }

  @Get('/demo')
  @ApiExcludeEndpoint()
  demo(@Res() res: Response) {
    if (!this.config.demoEnabled) {
      throw new HttpException(
        'Demo endpoints are disabled',
        HttpStatus.NOT_FOUND,
      );
    }
    const filePath = 'demo.html';
    if (existsSync(filePath)) {
      const fileContent = readFileSync(filePath, 'utf-8');
      res.type('html').send(fileContent);
    } else {
      res.status(404).send('Demo page not found');
    }
  }

  @Get('/ip')
  @ApiExcludeEndpoint()
  ip(@Req() req: Request) {
    if (!this.config.demoEnabled) {
      throw new HttpException(
        'Demo endpoints are disabled',
        HttpStatus.NOT_FOUND,
      );
    }
    const ip = this.ipService.extractIp(req);
    return { ip };
  }
}
