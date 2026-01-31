import { Injectable, Logger } from '@nestjs/common';
import { BaseConfigService } from '../config/base.config';
import { RedisService } from '../redis/redis.service';
import { promises as dns } from 'dns';

export interface SpamhausCheckResult {
  isListed: boolean;
  lists: string[];
}

@Injectable()
export class SpamhausService {
  private readonly log = new Logger(SpamhausService.name);

  // Spamhaus DNSBLs
  private readonly dnsblZones = [
    'zen.spamhaus.org', // Combined list (includes SBL, XBL, PBL)
  ];

  constructor(
    private readonly config: BaseConfigService,
    private readonly redis: RedisService,
  ) {}

  /**
   * Check an IP address against Spamhaus DNSBLs.
   */
  async checkIP(ip: string): Promise<SpamhausCheckResult> {
    if (!this.config.spamhaus.enabled) {
      return { isListed: false, lists: [] };
    }

    // Check cache first
    const cached = await this.redis.getCachedIpCheckResult<SpamhausCheckResult>(
      'spamhaus',
      ip,
    );
    if (cached) {
      this.log.debug(`Using cached Spamhaus result for IP ${ip}`);
      return cached;
    }

    try {
      const reversedIP = this.reverseIP(ip);
      if (!reversedIP) {
        this.log.warn(
          `Cannot check IPv6 address ${ip} with Spamhaus DNSBL (IPv6 not supported by this implementation)`,
        );
        const result = { isListed: false, lists: [] };
        // Cache negative result
        await this.redis.cacheIpCheckResult(
          'spamhaus',
          ip,
          result,
          this.config.spamhaus.cacheTtl,
        );
        return result;
      }

      const listedIn: string[] = [];

      for (const zone of this.dnsblZones) {
        const hostname = `${reversedIP}.${zone}`;

        try {
          // Create a promise that rejects after timeout
          const timeoutPromise = new Promise<never>((_, reject) => {
            setTimeout(
              () => reject(new Error('DNS lookup timeout')),
              this.config.spamhaus.timeoutMs,
            );
          });

          // Race between DNS lookup and timeout
          await Promise.race([dns.resolve4(hostname), timeoutPromise]);

          // If resolve succeeds, IP is listed
          listedIn.push(zone);
          this.log.debug(`IP ${ip} is listed in ${zone}`);
        } catch (error) {
          // NXDOMAIN means not listed, which is expected
          if (error instanceof Error && 'code' in error) {
            const dnsError = error as NodeJS.ErrnoException;
            if (dnsError.code !== 'ENOTFOUND' && dnsError.code !== 'ENODATA') {
              this.log.warn(
                `DNS lookup error for ${hostname}: ${error.message}`,
              );
            }
          }
        }
      }

      const isListed = listedIn.length > 0;
      const result = { isListed, lists: listedIn };

      // Cache the result
      await this.redis.cacheIpCheckResult(
        'spamhaus',
        ip,
        result,
        this.config.spamhaus.cacheTtl,
      );

      if (isListed) {
        this.log.log(`IP ${ip} is listed in Spamhaus: ${listedIn.join(', ')}`);
      } else {
        this.log.debug(`IP ${ip} is not listed in Spamhaus`);
      }

      return result;
    } catch (error) {
      this.log.error(
        `Failed to check IP ${ip} with Spamhaus: ${error instanceof Error ? error.message : 'Unknown error'}`,
      );
      // Return safe default on error (don't cache errors)
      return { isListed: false, lists: [] };
    }
  }

  /**
   * Reverse an IPv4 address for DNSBL lookup.
   * Returns null for IPv6 addresses (not supported by this basic implementation).
   */
  private reverseIP(ip: string): string | null {
    // Check if it's IPv6 (contains colons)
    if (ip.includes(':')) {
      return null;
    }

    // IPv4: reverse the octets
    const parts = ip.split('.');
    if (parts.length !== 4) {
      return null;
    }

    return parts.reverse().join('.');
  }
}
