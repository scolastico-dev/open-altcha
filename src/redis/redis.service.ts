import { Injectable, Logger } from '@nestjs/common';
import { BaseConfigService } from '../config/base.config';
import Redis from 'ioredis';

export interface IpStats {
  attempts: number;
  successes: number;
  failures: number;
  lastAttempt: number;
  challengeRequests: number;
}

interface InMemoryEntry<T> {
  data: T;
  expiresAt: number;
}

@Injectable()
export class RedisService {
  private readonly log = new Logger(RedisService.name);
  private client: Redis | null = null;
  private isEnabled: boolean;
  private inMemoryStore: Map<string, InMemoryEntry<string>> = new Map();
  private cleanupInterval: NodeJS.Timeout | null = null;

  constructor(private readonly baseConfig: BaseConfigService) {
    const config = baseConfig.redis;
    this.isEnabled = config.enabled;

    if (this.isEnabled) {
      this.client = new Redis(config.url, {
        keyPrefix: config.prefix,
        retryStrategy: (times) => {
          const delay = Math.min(times * 50, 2000);
          return delay;
        },
      });

      this.client.on('error', (err) => {
        this.log.error('Redis error:', err);
      });

      this.client.on('connect', () => {
        this.log.log('Redis connected successfully');
      });
    } else {
      this.log.warn('Redis disabled - using in-memory storage');
      this.startCleanupScheduler();
    }
  }

  private startCleanupScheduler(): void {
    // Clean up expired entries every 60 seconds
    this.cleanupInterval = setInterval(() => {
      const now = Date.now();
      let cleaned = 0;
      for (const [key, entry] of this.inMemoryStore.entries()) {
        if (entry.expiresAt <= now) {
          this.inMemoryStore.delete(key);
          cleaned++;
        }
      }
      if (cleaned > 0) {
        this.log.debug(
          `Cleaned up ${cleaned} expired entries from in-memory store`,
        );
      }
    }, 60000);
  }

  private setInMemory(key: string, value: string, ttlSeconds: number): void {
    const expiresAt = Date.now() + ttlSeconds * 1000;
    this.inMemoryStore.set(key, { data: value, expiresAt });
    this.log.debug(
      `Stored in-memory: ${key} (expires in ${ttlSeconds}s, total entries: ${this.inMemoryStore.size})`,
    );
  }

  private getInMemory(key: string): string | null {
    const entry = this.inMemoryStore.get(key);
    if (!entry) {
      return null;
    }
    if (entry.expiresAt <= Date.now()) {
      this.inMemoryStore.delete(key);
      return null;
    }
    return entry.data;
  }

  private deleteInMemory(key: string): void {
    this.inMemoryStore.delete(key);
  }

  async storeChallengeData(
    challengeId: string,
    data: {
      domain: string;
      strength: number;
      createdAt: number;
      ip: string;
    },
  ): Promise<void> {
    const key = `challenge:${challengeId}`;
    this.log.debug(
      `Storing challenge data for ${challengeId} (domain: ${data.domain}, ip: ${data.ip})`,
    );

    if (this.isEnabled && this.client) {
      await this.client.setex(
        key,
        this.baseConfig.redis.challengeTtl,
        JSON.stringify(data),
      );
    } else {
      this.setInMemory(
        key,
        JSON.stringify(data),
        this.baseConfig.redis.challengeTtl,
      );
    }
  }

  async getChallengeData(challengeId: string): Promise<{
    domain: string;
    strength: number;
    createdAt: number;
    ip: string;
  } | null> {
    const key = `challenge:${challengeId}`;
    let data: string | null = null;

    if (this.isEnabled && this.client) {
      data = await this.client.get(key);
    } else {
      data = this.getInMemory(key);
    }

    if (!data) {
      this.log.debug(`Challenge data not found for ${challengeId}`);
      return null;
    }

    this.log.debug(`Retrieved challenge data for ${challengeId}`);
    return JSON.parse(data) as {
      domain: string;
      strength: number;
      createdAt: number;
      ip: string;
    };
  }

  async deleteChallengeData(challengeId: string): Promise<void> {
    const key = `challenge:${challengeId}`;
    this.log.debug(`Deleting challenge data for ${challengeId}`);

    if (this.isEnabled && this.client) {
      await this.client.del(key);
    } else {
      this.deleteInMemory(key);
    }
  }

  /**
   * Atomically gets and deletes challenge data to prevent race conditions.
   * This prevents parallel validation attempts from both passing the check.
   */
  async getChallengeDataAndDelete(challengeId: string): Promise<{
    domain: string;
    strength: number;
    createdAt: number;
    ip: string;
  } | null> {
    const key = `challenge:${challengeId}`;
    let data: string | null = null;

    if (this.isEnabled && this.client) {
      // Use GETDEL for atomic get-and-delete operation
      data = await this.client.getdel(key);
    } else {
      // For in-memory, we need to manually ensure atomicity
      data = this.getInMemory(key);
      if (data) {
        this.deleteInMemory(key);
      }
    }

    if (!data) {
      this.log.debug(
        `Challenge data not found or already deleted for ${challengeId}`,
      );
      return null;
    }

    this.log.debug(`Retrieved and deleted challenge data for ${challengeId}`);
    return JSON.parse(data) as {
      domain: string;
      strength: number;
      createdAt: number;
      ip: string;
    };
  }

  async getIpStats(ip: string, domain: string): Promise<IpStats> {
    const key = `ip_stats:${domain}:${ip}`;
    let data: string | null = null;

    if (this.isEnabled && this.client) {
      data = await this.client.get(key);
    } else {
      data = this.getInMemory(key);
    }

    if (!data) {
      this.log.debug(`No stats found for IP ${ip} on domain ${domain}`);
      return {
        attempts: 0,
        successes: 0,
        failures: 0,
        lastAttempt: 0,
        challengeRequests: 0,
      };
    }

    const stats = JSON.parse(data) as IpStats;
    // Ensure challengeRequests exists for backward compatibility
    if (stats.challengeRequests === undefined) {
      stats.challengeRequests = 0;
    }
    this.log.debug(
      `Retrieved stats for IP ${ip} on domain ${domain}: ${JSON.stringify(stats)}`,
    );
    return stats;
  }

  async updateIpStats(
    ip: string,
    domain: string,
    success: boolean,
  ): Promise<void> {
    const key = `ip_stats:${domain}:${ip}`;
    const stats = await this.getIpStats(ip, domain);

    stats.attempts += 1;
    if (success) {
      stats.successes += 1;
    } else {
      stats.failures += 1;
    }
    stats.lastAttempt = Date.now();

    this.log.debug(
      `Updating stats for IP ${ip} on domain ${domain}: attempts=${stats.attempts}, successes=${stats.successes}, failures=${stats.failures}`,
    );

    // Store stats for 24 hours
    if (this.isEnabled && this.client) {
      await this.client.setex(key, 86400, JSON.stringify(stats));
    } else {
      this.setInMemory(key, JSON.stringify(stats), 86400);
    }
  }

  /**
   * Increments the challenge request counter for an IP on a domain.
   * This tracks how many challenges have been requested (regardless of validation).
   */
  async incrementIpChallengeRequests(
    ip: string,
    domain: string,
  ): Promise<void> {
    const key = `ip_stats:${domain}:${ip}`;
    const stats = await this.getIpStats(ip, domain);

    stats.challengeRequests += 1;
    stats.lastAttempt = Date.now();

    this.log.debug(
      `Incrementing challenge requests for IP ${ip} on domain ${domain}: challengeRequests=${stats.challengeRequests}`,
    );

    // Store stats for 24 hours
    if (this.isEnabled && this.client) {
      await this.client.setex(key, 86400, JSON.stringify(stats));
    } else {
      this.setInMemory(key, JSON.stringify(stats), 86400);
    }
  }

  async getActiveIpCount(): Promise<number> {
    if (this.isEnabled && this.client) {
      const keys = await this.client.keys('ip_stats:*');
      this.log.debug(`Active IP count: ${keys.length}`);
      return keys.length;
    } else {
      const now = Date.now();
      let count = 0;
      for (const [key, entry] of this.inMemoryStore.entries()) {
        if (key.startsWith('ip_stats:') && entry.expiresAt > now) {
          count++;
        }
      }
      this.log.debug(`Active IP count (in-memory): ${count}`);
      return count;
    }
  }

  async storeVerificationCode(
    challengeId: string,
    data: {
      code: string;
      domain: string;
      ip: string;
      strength: number;
    },
  ): Promise<void> {
    const key = `verification_code:${challengeId}`;
    this.log.debug(
      `Storing verification code for challenge ${challengeId} (domain: ${data.domain})`,
    );

    // Store for 5 minutes (300 seconds)
    if (this.isEnabled && this.client) {
      await this.client.setex(key, 300, JSON.stringify(data));
    } else {
      this.setInMemory(key, JSON.stringify(data), 300);
    }
  }

  async getVerificationCode(challengeId: string): Promise<{
    code: string;
    domain: string;
    ip: string;
    strength: number;
  } | null> {
    const key = `verification_code:${challengeId}`;
    let data: string | null = null;

    if (this.isEnabled && this.client) {
      data = await this.client.get(key);
    } else {
      data = this.getInMemory(key);
    }

    if (!data) {
      this.log.debug(`Verification code not found for ${challengeId}`);
      return null;
    }

    this.log.debug(`Retrieved verification code for ${challengeId}`);
    return JSON.parse(data) as {
      code: string;
      domain: string;
      ip: string;
      strength: number;
    };
  }

  async deleteVerificationCode(challengeId: string): Promise<void> {
    const key = `verification_code:${challengeId}`;
    this.log.debug(`Deleting verification code for ${challengeId}`);

    if (this.isEnabled && this.client) {
      await this.client.del(key);
    } else {
      this.deleteInMemory(key);
    }
  }

  /**
   * Checks if a signature has already been used (for replay attack prevention)
   * @param signature The signature to check
   * @returns true if signature has been used, false otherwise
   */
  async isSignatureUsed(signature: string): Promise<boolean> {
    const key = `used_signature:${signature}`;

    if (this.isEnabled && this.client) {
      const exists = await this.client.exists(key);
      return exists === 1;
    } else {
      const data = this.getInMemory(key);
      return data !== null;
    }
  }

  /**
   * Marks a signature as used with a TTL (for replay attack prevention)
   * @param signature The signature to mark as used
   * @param ttlSeconds Time to live in seconds (should match maxAge)
   */
  async markSignatureAsUsed(
    signature: string,
    ttlSeconds: number,
  ): Promise<void> {
    const key = `used_signature:${signature}`;
    this.log.debug(
      `Marking signature as used with TTL ${ttlSeconds}s: ${signature.substring(0, 16)}...`,
    );

    if (this.isEnabled && this.client) {
      await this.client.setex(key, ttlSeconds, 'used');
    } else {
      this.setInMemory(key, 'used', ttlSeconds);
    }
  }

  /**
   * Stores the result of an IP check (Spamhaus, AbuseIPDB, etc.) in cache
   * @param service The service name (e.g., 'spamhaus', 'abuseipdb')
   * @param ip The IP address that was checked
   * @param result The check result (serialized as JSON)
   * @param ttlSeconds Time to live in seconds
   */
  async cacheIpCheckResult(
    service: string,
    ip: string,
    result: object,
    ttlSeconds: number,
  ): Promise<void> {
    const key = `ip_check:${service}:${ip}`;
    this.log.debug(
      `Caching ${service} check result for IP ${ip} with TTL ${ttlSeconds}s`,
    );

    if (this.isEnabled && this.client) {
      await this.client.setex(key, ttlSeconds, JSON.stringify(result));
    } else {
      this.setInMemory(key, JSON.stringify(result), ttlSeconds);
    }
  }

  /**
   * Retrieves a cached IP check result
   * @param service The service name (e.g., 'spamhaus', 'abuseipdb')
   * @param ip The IP address to check
   * @returns The cached result or null if not found/expired
   */
  async getCachedIpCheckResult<T>(
    service: string,
    ip: string,
  ): Promise<T | null> {
    const key = `ip_check:${service}:${ip}`;
    let data: string | null = null;

    if (this.isEnabled && this.client) {
      data = await this.client.get(key);
    } else {
      data = this.getInMemory(key);
    }

    if (!data) {
      this.log.debug(`No cached ${service} result for IP ${ip}`);
      return null;
    }

    this.log.debug(`Retrieved cached ${service} result for IP ${ip}`);
    return JSON.parse(data) as T;
  }

  /**
   * Checks if an IP has already been reported to AbuseIPDB within the last 24 hours
   * @param ip The IP address to check
   * @returns true if IP was already reported, false otherwise
   */
  async isIpReportedToAbuseIPDB(ip: string): Promise<boolean> {
    const key = `reported_ip:abuseipdb:${ip}`;

    if (this.isEnabled && this.client) {
      const exists = await this.client.exists(key);
      return exists === 1;
    } else {
      const data = this.getInMemory(key);
      return data !== null;
    }
  }

  /**
   * Marks an IP as reported to AbuseIPDB with a 24-hour TTL
   * @param ip The IP address that was reported
   */
  async markIpAsReportedToAbuseIPDB(ip: string): Promise<void> {
    const key = `reported_ip:abuseipdb:${ip}`;
    const ttlSeconds = 86400; // 24 hours
    this.log.debug(`Marking IP ${ip} as reported to AbuseIPDB (TTL: 24 hours)`);

    if (this.isEnabled && this.client) {
      await this.client.setex(key, ttlSeconds, 'reported');
    } else {
      this.setInMemory(key, 'reported', ttlSeconds);
    }
  }

  async onModuleDestroy() {
    if (this.cleanupInterval) {
      clearInterval(this.cleanupInterval);
      this.cleanupInterval = null;
    }
    if (this.client) {
      this.log.debug('Closing Redis connection');
      await this.client.quit();
    }
  }
}
