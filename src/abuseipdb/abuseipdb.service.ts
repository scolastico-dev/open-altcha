import { Injectable, Logger } from '@nestjs/common';
import { BaseConfigService } from '../config/base.config';
import { RedisService } from '../redis/redis.service';
import axios from 'axios';

export interface AbuseIPDBCheckResult {
  isListed: boolean;
  abuseConfidenceScore: number;
  usageType?: string;
  domain?: string;
  totalReports?: number;
}

@Injectable()
export class AbuseIPDBService {
  private readonly log = new Logger(AbuseIPDBService.name);
  private readonly baseUrl = 'https://api.abuseipdb.com/api/v2';

  constructor(
    private readonly config: BaseConfigService,
    private readonly redis: RedisService,
  ) {}

  /**
   * Check an IP address against AbuseIPDB.
   */
  async checkIP(ip: string): Promise<AbuseIPDBCheckResult> {
    if (!this.config.abuseipdb.checkEnabled) {
      return { isListed: false, abuseConfidenceScore: 0 };
    }

    if (!this.config.abuseipdb.apiKey) {
      this.log.warn(
        'AbuseIPDB checking is enabled but no API key is configured',
      );
      return { isListed: false, abuseConfidenceScore: 0 };
    }

    // Check cache first
    const cached =
      await this.redis.getCachedIpCheckResult<AbuseIPDBCheckResult>(
        'abuseipdb',
        ip,
      );
    if (cached) {
      this.log.debug(`Using cached AbuseIPDB result for IP ${ip}`);
      return cached;
    }

    try {
      const response = await axios.get<{
        data: {
          abuseConfidenceScore?: number;
          usageType?: string;
          domain?: string;
          totalReports?: number;
        };
      }>(`${this.baseUrl}/check`, {
        params: {
          ipAddress: ip,
          maxAgeInDays: this.config.abuseipdb.maxAgeDays,
          verbose: true,
        },
        headers: {
          Key: this.config.abuseipdb.apiKey,
          Accept: 'application/json',
        },
        timeout: 5000,
      });

      const data = response.data.data;
      const abuseConfidenceScore: number = data.abuseConfidenceScore || 0;
      const isListed =
        abuseConfidenceScore >= this.config.abuseipdb.confidenceThreshold;

      const result = {
        isListed,
        abuseConfidenceScore,
        usageType: data.usageType,
        domain: data.domain,
        totalReports: data.totalReports,
      };

      // Cache the result
      await this.redis.cacheIpCheckResult(
        'abuseipdb',
        ip,
        result,
        this.config.abuseipdb.cacheTtl,
      );

      this.log.debug(
        `AbuseIPDB check for ${ip}: confidence=${abuseConfidenceScore}, listed=${isListed}`,
      );

      return result;
    } catch (error) {
      this.log.error(
        `Failed to check IP ${ip} with AbuseIPDB: ${error instanceof Error ? error.message : 'Unknown error'}`,
      );
      // Return safe default on error (don't cache errors)
      return { isListed: false, abuseConfidenceScore: 0 };
    }
  }

  /**
   * Report an IP address to AbuseIPDB.
   * Checks if IP was already reported within the last 24 hours to avoid duplicates.
   */
  async reportIP(
    ip: string,
    categories: number[],
    comment: string,
  ): Promise<boolean> {
    if (!this.config.abuseipdb.reportEnabled) {
      return false;
    }

    if (!this.config.abuseipdb.apiKey) {
      this.log.warn(
        'AbuseIPDB reporting is enabled but no API key is configured',
      );
      return false;
    }

    // Check if this IP was already reported within the last 24 hours
    const alreadyReported = await this.redis.isIpReportedToAbuseIPDB(ip);
    if (alreadyReported) {
      this.log.debug(
        `IP ${ip} was already reported to AbuseIPDB within the last 24 hours, skipping duplicate report`,
      );
      return false;
    }

    try {
      const formData = new URLSearchParams();
      formData.append('ip', ip);
      formData.append('categories', categories.join(','));
      formData.append('comment', comment);

      await axios.post(`${this.baseUrl}/report`, formData, {
        headers: {
          Key: this.config.abuseipdb.apiKey,
          Accept: 'application/json',
          'Content-Type': 'application/x-www-form-urlencoded',
        },
        timeout: 5000,
      });

      // Mark IP as reported for 24 hours
      await this.redis.markIpAsReportedToAbuseIPDB(ip);

      this.log.log(`Reported IP ${ip} to AbuseIPDB: ${comment}`);
      return true;
    } catch (error) {
      this.log.error(
        `Failed to report IP ${ip} to AbuseIPDB: ${error instanceof Error ? error.message : 'Unknown error'}`,
      );
      return false;
    }
  }
}
