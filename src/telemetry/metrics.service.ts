import { Injectable } from '@nestjs/common';
import { metrics } from '@opentelemetry/api';
import { BaseConfigService } from '../config/base.config';

@Injectable()
export class MetricsService {
  private readonly meter = metrics.getMeter('altcha-server');
  private enabled: boolean;

  constructor(private readonly config: BaseConfigService) {
    this.enabled = this.config.otlp.enabled;
  }

  // Counters
  private readonly captchaGeneratedCounter = this.meter.createCounter(
    'altcha.captcha.generated',
    {
      description: 'Number of ALTCHA challenges generated',
    },
  );

  private readonly captchaValidatedCounter = this.meter.createCounter(
    'altcha.captcha.validated',
    {
      description: 'Number of ALTCHA challenges validated',
    },
  );

  private readonly captchaValidationSuccessCounter = this.meter.createCounter(
    'altcha.captcha.validation.success',
    {
      description: 'Number of successful ALTCHA validations',
    },
  );

  private readonly captchaValidationFailureCounter = this.meter.createCounter(
    'altcha.captcha.validation.failure',
    {
      description: 'Number of failed ALTCHA validations',
    },
  );

  // Histograms
  private readonly captchaStrengthHistogram = this.meter.createHistogram(
    'altcha.captcha.strength',
    {
      description: 'Distribution of ALTCHA challenge strength levels',
    },
  );

  private readonly captchaSolveTimeHistogram = this.meter.createHistogram(
    'altcha.captcha.solve_time',
    {
      description: 'Time taken to solve ALTCHA challenges (in seconds)',
    },
  );

  // Gauges (via Observable)
  private readonly activeIpGauge = this.meter.createObservableGauge(
    'altcha.active_ips',
    {
      description: 'Number of unique IPs with active challenges',
    },
  );

  recordCaptchaGenerated(domain: string, strength: number) {
    if (!this.enabled) return;
    this.captchaGeneratedCounter.add(1, { domain });
    this.captchaStrengthHistogram.record(strength, {
      domain,
      type: 'generated',
    });
  }

  recordCaptchaValidated(
    domain: string,
    success: boolean,
    strength: number,
    solveTime?: number,
  ) {
    if (!this.enabled) return;
    this.captchaValidatedCounter.add(1, {
      domain,
      success: success.toString(),
    });

    if (success) {
      this.captchaValidationSuccessCounter.add(1, { domain });
      if (solveTime) {
        this.captchaSolveTimeHistogram.record(solveTime, { domain });
      }
    } else {
      this.captchaValidationFailureCounter.add(1, { domain });
    }

    this.captchaStrengthHistogram.record(strength, {
      domain,
      type: 'validated',
    });
  }

  recordThreatDetection(
    ip: string,
    threatLevel: string,
    strengthIncrease: number,
  ) {
    if (!this.enabled) return;
    const threatCounter = this.meter.createCounter('altcha.threat.detected', {
      description: 'Number of threats detected by CrowdSec',
    });

    threatCounter.add(1, { threat_level: threatLevel });

    const strengthIncreaseHistogram = this.meter.createHistogram(
      'altcha.threat.strength_increase',
      {
        description: 'Strength increase due to threat detection',
      },
    );

    strengthIncreaseHistogram.record(strengthIncrease, {
      threat_level: threatLevel,
    });
  }
}
