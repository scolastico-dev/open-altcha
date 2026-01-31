import {
  Controller,
  Get,
  Param,
  Query,
  Res,
  HttpException,
  HttpStatus,
  Logger,
} from '@nestjs/common';
import {
  ApiTags,
  ApiOperation,
  ApiResponse,
  ApiParam,
  ApiQuery,
} from '@nestjs/swagger';
import type { Response } from 'express';
import { EspeakService } from './espeak.service';
import { RedisService } from '../redis/redis.service';
import { createReadStream } from 'fs';

@ApiTags('espeak')
@Controller('espeak')
export class EspeakController {
  private readonly log = new Logger(EspeakController.name);

  constructor(
    private readonly espeakService: EspeakService,
    private readonly redisService: RedisService,
  ) {}

  @Get(':challengeId.wav')
  @ApiOperation({ summary: 'Get audio captcha for a challenge' })
  @ApiParam({
    name: 'challengeId',
    description: 'The challenge ID',
    type: String,
  })
  @ApiQuery({
    name: 'language',
    description: 'Two-digit language code (e.g., en, de)',
    required: false,
    type: String,
  })
  @ApiResponse({
    status: 200,
    description: 'Audio file returned successfully',
  })
  @ApiResponse({
    status: 404,
    description: 'Challenge not found or expired',
  })
  @ApiResponse({
    status: 500,
    description: 'Audio generation failed',
  })
  async getAudio(
    @Param('challengeId') challengeId: string,
    @Query('language') language: string = 'en',
    @Res() res: Response,
  ): Promise<void> {
    this.log.debug(
      `Audio requested for challenge ${challengeId}, language: ${language}`,
    );

    try {
      // Validate language parameter (only allow 2-letter codes)
      if (!/^[a-z]{2}$/i.test(language)) {
        throw new HttpException(
          'Invalid language code. Must be a two-letter code (e.g., en, de)',
          HttpStatus.BAD_REQUEST,
        );
      }

      // Get challenge data from Redis to retrieve the verification code
      const verificationData =
        await this.redisService.getVerificationCode(challengeId);

      if (!verificationData || !verificationData.code) {
        this.log.warn(
          `Challenge ${challengeId} not found or has no verification code`,
        );
        throw new HttpException(
          'Challenge not found or expired',
          HttpStatus.NOT_FOUND,
        );
      }

      // Check if audio file already exists
      let audioPath = await this.espeakService.getAudioPath(challengeId);

      if (!audioPath) {
        // Generate audio file
        audioPath = await this.espeakService.generateAudio(
          challengeId,
          verificationData.code,
          language.toLowerCase(),
        );
      }

      // Stream the audio file
      res.setHeader('Content-Type', 'audio/wav');
      res.setHeader(
        'Content-Disposition',
        `inline; filename="${challengeId}.wav"`,
      );
      res.setHeader('Cache-Control', 'private, max-age=300'); // Cache for 5 minutes

      const fileStream = createReadStream(audioPath);

      fileStream.on('error', (error) => {
        this.log.error(`Error streaming audio file: ${error}`);
        if (!res.headersSent) {
          res.status(500).json({ error: 'Failed to stream audio file' });
        }
      });

      fileStream.pipe(res);
    } catch (error) {
      this.log.error(`Failed to serve audio: ${error}`);

      if (error instanceof HttpException) {
        throw error;
      }

      throw new HttpException(
        'Failed to generate or serve audio',
        HttpStatus.INTERNAL_SERVER_ERROR,
      );
    }
  }
}
