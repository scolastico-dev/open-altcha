import { Injectable, Logger } from '@nestjs/common';
import axios, { AxiosInstance } from 'axios';
import { BaseConfigService } from '../config/base.config';

export enum ThreatLevel {
  NONE = 'none',
  LOW = 'low',
  MEDIUM = 'medium',
  HIGH = 'high',
  CRITICAL = 'critical',
}

export interface ThreatInfo {
  level: ThreatLevel;
  strengthIncrease: number;
  reason: string;
}

interface CrowdSecDecision {
  type?: string;
  scope?: string;
  scenario?: string;
}

@Injectable()
export class CrowdSecService {
  private readonly log = new Logger(CrowdSecService.name);
  private client: AxiosInstance | null = null;
  private isEnabled: boolean;

  constructor(private readonly baseConfig: BaseConfigService) {
    const config = baseConfig.crowdsec;
    this.isEnabled = config.enabled && !!config.apiKey;

    if (this.isEnabled) {
      this.client = axios.create({
        baseURL: config.lapiUrl,
        headers: {
          'X-Api-Key': config.apiKey,
        },
        timeout: 5000,
      });

      this.log.log('CrowdSec integration enabled');
      this.log.debug(`CrowdSec LAPI URL: ${config.lapiUrl}`);
    } else {
      this.log.warn('CrowdSec integration disabled');
    }
  }

  async checkIpThreat(ip: string): Promise<ThreatInfo> {
    if (!this.isEnabled || !this.client) {
      return {
        level: ThreatLevel.NONE,
        strengthIncrease: 0,
        reason: 'CrowdSec disabled',
      };
    }

    try {
      this.log.debug(`Checking IP threat for ${ip} with CrowdSec`);
      // Check if IP is in the decision database
      const response = await this.client.get('/v1/decisions', {
        params: {
          ip: ip,
        },
      });

      if (
        response.data &&
        Array.isArray(response.data) &&
        response.data.length > 0
      ) {
        const decision = response.data[0] as CrowdSecDecision;
        const type = decision.type || 'unknown';
        const scope = decision.scope || 'unknown';

        this.log.debug(
          `CrowdSec decision found for ${ip}: type=${type}, scope=${scope}`,
        );

        // Determine threat level based on decision type
        let level = ThreatLevel.MEDIUM;
        let strengthIncrease = this.baseConfig.crowdsec.minStrengthIncrease;

        if (type === 'ban' || scope === 'Ip') {
          level = ThreatLevel.HIGH;
          strengthIncrease = this.baseConfig.crowdsec.maxStrengthIncrease;
        } else if (type === 'captcha') {
          level = ThreatLevel.MEDIUM;
          strengthIncrease = Math.floor(
            (this.baseConfig.crowdsec.minStrengthIncrease +
              this.baseConfig.crowdsec.maxStrengthIncrease) /
              2,
          );
        }

        return {
          level,
          strengthIncrease,
          reason: `CrowdSec decision: ${type} (${decision.scenario || 'unknown scenario'})`,
        };
      }

      this.log.debug(`No CrowdSec threat detected for ${ip}`);
      return {
        level: ThreatLevel.NONE,
        strengthIncrease: 0,
        reason: 'No threat detected',
      };
    } catch (error) {
      this.log.error(`Error checking IP with CrowdSec:`, error);
      // On error, return no threat to avoid blocking legitimate users
      return {
        level: ThreatLevel.NONE,
        strengthIncrease: 0,
        reason: 'CrowdSec check failed',
      };
    }
  }

  reportFailedAttempt(ip: string, domain: string): void {
    // This could be extended to report failed attempts to CrowdSec
    // For now, it's a placeholder for future implementation
    if (!this.isEnabled) return;

    this.log.debug(`Suspicious activity from ${ip} on domain ${domain}`);
  }
}
