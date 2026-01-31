# OpenALTCHA Server

OpenALTCHA Server is a self-hosted, high-performance challenge-response system designed to protect web applications from bots and automated abuse. It is a drop-in replacement for [ALTCHA's Sentinel](https://altcha.org/), implementing advanced security features like dynamic difficulty, IP reputation checks, and anti-tampering signatures.

Visit our hosted demo at [https://altcha.scolasti.co/demo?domain=altcha.scolasti.co](https://altcha.scolasti.co/demo?domain=altcha.scolasti.co) to give it a try.

## Features

* **Dynamic Difficulty:** Automatically adjusts CAPTCHA complexity based on the client's threat level.
* **CrowdSec Integration:** Checks IPs against the CrowdSec LAPI.
* **AbuseIPDB:** Leverages real-time IP reputation scores.
* **Spamhaus DNSBL:** Checks for IPs listed in known spam databases.
* **Anti-Spam Tools:** Built-in detection for disposable email domains.
* **Stateless Backend Verification:** Issue HMAC signatures that allow your backend to verify a challenge was solved without querying a database.
* **Anti-Tampering:** Signs form fields alongside the challenge to prevent attackers from "reusing" a valid solution with different form data.
* **Observability:** Built-in Prometheus metrics and OTLP tracing support.
* **Flexible Storage:** Supports Redis for distributed environments or an optimized in-memory store for simple setups.

## Installation

The easiest way to run OpenALTCHA is using Docker.

```yaml
services:
  app:
    image: ghcr.io/scolastico-dev/open-altcha:latest
    ports:
      - "3000:3000"
    depends_on:
      redis:
        condition: service_healthy
      jaeger:
        condition: service_healthy
    healthcheck:
      test: ["CMD", "curl", "-f", "http://localhost:3000/health"]
      interval: 30s
      timeout: 10s
      retries: 3
      start_period: 10s
    tmpfs:
      - /tmp
    environment:
      - PORT=3000
      - DOMAIN_LIST=example,test
      - DOMAIN_EXAMPLE_ORIGINS=example.com,localhost
      - DOMAIN_EXAMPLE_KEY=your-secret-hmac-key-here
      - DOMAIN_TEST_ORIGINS=test.com,www.test.com
      - DOMAIN_TEST_KEY=another-secret-key
      - REDIS_ENABLED=true
      - REDIS_URL=redis://redis:6379
      - OTLP_ENABLED=true
      - OTLP_TRACE_ENDPOINT=http://jaeger:4318/v1/traces
      - OTLP_METRICS_ENDPOINT=http://jaeger:4318/v1/metrics
      - OTLP_SERVICE_NAME=altcha-server
      # AbuseIPDB Integration
      # - ABUSEIPDB_CHECK_ENABLED=true
      # - ABUSEIPDB_API_KEY=your-abuseipdb-api-key-here
      # Spamhaus Integration
      # - SPAMHAUS_ENABLED=true
      # CrowdSec Integration
      # - CROWDSEC_ENABLED=true
      # - CROWDSEC_LAPI_URL=http://host.docker.internal:8080
      # - CROWDSEC_API_KEY=your-crowdsec-api-key-here
      # - CROWDSEC_MIN_STRENGTH_INCREASE=20
      # - CROWDSEC_MAX_STRENGTH_INCREASE=50
    # Uncomment to allow access to CrowdSec running on Docker host
    # extra_hosts:
    #   - "host.docker.internal:host-gateway"

  redis:
    image: redis:alpine
    healthcheck:
      test: ["CMD", "redis-cli", "ping"]
      interval: 10s
      timeout: 5s
      retries: 5

  jaeger:
    image: jaegertracing/all-in-one:latest
    ports:
      - "16686:16686"
      - "4318:4318"
    healthcheck:
      test: ["CMD", "curl", "-f", "http://localhost:14269/health"]
      interval: 10s
      timeout: 5s
      retries: 5
    environment:
      - COLLECTOR_OTLP_ENABLED=true
```

## Configuration

OpenALTCHA is configured primarily through environment variables.

### Core Variables

| Variable | Description | Default |
| --- | --- | --- |
| `PORT` | The port the server listens on. | `3000` |
| `DOMAIN_LIST` | Comma-separated list of domain identifiers. | (Required) |
| `TRUSTED_IP_HEADER` | Header to trust for client IP (e.g., `X-Forwarded-For`). | `''` |
| `REDIS_ENABLED` | Enable Redis for challenge storage and rate limiting. | `false` |

### Domain-Specific Settings

For every domain in `DOMAIN_LIST` (e.g., `example`), you must configure:

* `DOMAIN_EXAMPLE_ORIGINS`: Allowed CORS origins.
* `DOMAIN_EXAMPLE_KEY`: The secret key used to sign challenges.
* `DOMAIN_EXAMPLE_MIN_STRENGTH`: Minimum PoW difficulty.

### Integration Envs

* **CrowdSec:** `CROWDSEC_ENABLED`, `CROWDSEC_LAPI_URL`, `CROWDSEC_API_KEY`.
* **AbuseIPDB:** `ABUSEIPDB_CHECK_ENABLED`, `ABUSEIPDB_API_KEY`.
* **Spamhaus:** `SPAMHAUS_ENABLED`.

### Full Documentation

For a complete list of all available environment variables and their detailed descriptions, please visit our **[Environment Documentation Page](https://scolastico-dev.github.io/open-altcha/)**.

## API Usage

The server provides a Swagger UI for API exploration at `/swagger`.

1. **GET `/captcha/challenge`**: Request a new challenge for a domain.
2. **POST `/captcha/validate`**: Submit the PoW solution for validation. This returns a signature if valid.
3. **POST `/captcha/verify-backend`**: Used by your backend to verify the signature provided by the client.
