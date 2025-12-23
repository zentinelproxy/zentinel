# Sentinel Service Level Objectives (SLOs)

## Overview

This document defines the Service Level Objectives (SLOs) for the Sentinel reverse proxy platform. These SLOs represent our commitment to service reliability and guide our operational decisions, feature development, and incident response priorities.

## Definitions

- **SLI (Service Level Indicator)**: A quantitative measure of service behavior
- **SLO (Service Level Objective)**: A target value or range for an SLI
- **SLA (Service Level Agreement)**: A contract with users (typically more relaxed than SLO)
- **Error Budget**: The amount of unreliability we can tolerate (100% - SLO)

## Service Level Indicators (SLIs)

### 1. Availability
**Definition**: The percentage of successful requests (non-5xx responses) over total requests.

**Measurement**:
```promql
(
  sum(rate(sentinel_requests_total{status!~"5.."}[5m]))
  /
  sum(rate(sentinel_requests_total[5m]))
) * 100
```

### 2. Latency
**Definition**: The percentage of requests served within acceptable latency thresholds.

**Measurement**:
```promql
(
  sum(rate(sentinel_request_duration_seconds_bucket{le="0.1"}[5m]))
  /
  sum(rate(sentinel_request_duration_seconds_count[5m]))
) * 100
```

### 3. Error Rate
**Definition**: The percentage of requests that result in errors (4xx and 5xx responses).

**Measurement**:
```promql
(
  sum(rate(sentinel_requests_total{status=~"[45].."}[5m]))
  /
  sum(rate(sentinel_requests_total[5m]))
) * 100
```

### 4. Throughput
**Definition**: The system's ability to handle the expected request volume.

**Measurement**:
```promql
sum(rate(sentinel_requests_total[5m]))
```

## Service Level Objectives

### Production Environment

| SLI | SLO Target | Error Budget | Measurement Window |
|-----|------------|--------------|-------------------|
| **Availability** | 99.95% | 0.05% (21.6 min/month) | 30 days |
| **Latency (P50)** | < 50ms for 99.9% | 0.1% | 30 days |
| **Latency (P99)** | < 500ms for 99% | 1% | 30 days |
| **Error Rate** | < 0.1% | 0.1% | 30 days |
| **Throughput** | > 10,000 RPS | N/A | 5 minutes |

### Staging Environment

| SLI | SLO Target | Error Budget | Measurement Window |
|-----|------------|--------------|-------------------|
| **Availability** | 99.5% | 0.5% (3.6 hrs/month) | 30 days |
| **Latency (P50)** | < 100ms for 99% | 1% | 30 days |
| **Latency (P99)** | < 1000ms for 95% | 5% | 30 days |
| **Error Rate** | < 1% | 1% | 30 days |
| **Throughput** | > 1,000 RPS | N/A | 5 minutes |

## Error Budget Policy

### Error Budget Calculation
```
Error Budget = 100% - SLO Target
Monthly Error Budget (minutes) = 43,200 * (Error Budget / 100)
```

### Error Budget Consumption Actions

| Consumption | Action | Description |
|-------------|--------|-------------|
| **< 25%** | Normal Operations | Continue feature development and deployments |
| **25-50%** | Increased Caution | Review recent changes, increase monitoring |
| **50-75%** | Reliability Focus | Prioritize reliability improvements, limit risky changes |
| **75-90%** | Feature Freeze | Stop feature development, focus on reliability |
| **> 90%** | Emergency Mode | All hands on reliability, postmortem required |
| **> 100%** | SLO Breach | Incident response, executive escalation |

## Multi-Window SLOs

To balance short-term reliability with long-term goals, we use multiple measurement windows:

### Short-term (1 hour)
- **Purpose**: Detect immediate issues
- **Availability SLO**: 99.9%
- **Action**: Page on-call if breached

### Medium-term (24 hours)
- **Purpose**: Daily reliability tracking
- **Availability SLO**: 99.95%
- **Action**: Alert engineering team if breached

### Long-term (30 days)
- **Purpose**: Monthly reliability commitment
- **Availability SLO**: 99.95%
- **Action**: Executive review if breached

## Alerting Rules

### Critical Alerts (Page On-Call)

#### 1. Availability SLO Breach
```yaml
alert: SentinelAvailabilitySLOBreach
expr: |
  (
    sum(rate(sentinel_requests_total{status!~"5.."}[5m]))
    /
    sum(rate(sentinel_requests_total[5m]))
  ) < 0.999
for: 5m
labels:
  severity: critical
  team: platform
annotations:
  summary: "Availability below 99.9% SLO"
  description: "Current availability: {{ $value | humanizePercentage }}"
  runbook_url: "https://sentinel.rs/runbooks/availability-slo-breach"
```

#### 2. Latency SLO Breach
```yaml
alert: SentinelLatencySLOBreach
expr: |
  histogram_quantile(0.99, 
    sum(rate(sentinel_request_duration_seconds_bucket[5m])) by (le)
  ) > 0.5
for: 5m
labels:
  severity: critical
  team: platform
annotations:
  summary: "P99 latency above 500ms SLO"
  description: "Current P99 latency: {{ $value | humanizeDuration }}"
  runbook_url: "https://sentinel.rs/runbooks/latency-slo-breach"
```

#### 3. Complete Outage
```yaml
alert: SentinelCompleteOutage
expr: up{job="sentinel-proxy"} == 0
for: 1m
labels:
  severity: critical
  team: platform
annotations:
  summary: "Sentinel proxy is completely down"
  description: "No sentinel proxy instances are responding"
  runbook_url: "https://sentinel.rs/runbooks/complete-outage"
```

### Warning Alerts (Notify Team)

#### 1. Error Budget Burn Rate
```yaml
alert: SentinelHighErrorBudgetBurnRate
expr: |
  (
    1 - (
      sum(rate(sentinel_requests_total{status!~"5.."}[1h]))
      /
      sum(rate(sentinel_requests_total[1h]))
    )
  ) > 0.001  # Burning >6x the hourly budget
for: 5m
labels:
  severity: warning
  team: platform
annotations:
  summary: "High error budget burn rate"
  description: "Burning error budget at {{ $value | humanizePercentage }} per hour"
  runbook_url: "https://sentinel.rs/runbooks/error-budget-burn"
```

#### 2. Elevated Error Rate
```yaml
alert: SentinelElevatedErrorRate
expr: |
  sum(rate(sentinel_requests_total{status=~"5.."}[5m])) > 10
for: 10m
labels:
  severity: warning
  team: platform
annotations:
  summary: "Elevated 5xx error rate"
  description: "{{ $value }} errors per second"
  runbook_url: "https://sentinel.rs/runbooks/elevated-errors"
```

#### 3. WAF High Block Rate
```yaml
alert: SentinelWAFHighBlockRate
expr: |
  sum(rate(waf_requests_blocked_total[5m])) > 100
for: 5m
labels:
  severity: warning
  team: security
annotations:
  summary: "WAF blocking high number of requests"
  description: "{{ $value }} requests per second being blocked"
  runbook_url: "https://sentinel.rs/runbooks/waf-high-blocks"
```

### Info Alerts (Track Trends)

#### 1. Approaching SLO Limit
```yaml
alert: SentinelApproachingSLO
expr: |
  (
    sum(rate(sentinel_requests_total{status!~"5.."}[24h]))
    /
    sum(rate(sentinel_requests_total[24h]))
  ) < 0.9997  # 99.97% availability (approaching 99.95% SLO)
for: 30m
labels:
  severity: info
  team: platform
annotations:
  summary: "Availability approaching SLO limit"
  description: "24h availability: {{ $value | humanizePercentage }}"
```

## SLO Reviews

### Weekly Review
- Current SLO performance
- Error budget consumption rate
- Incident impact on SLOs
- Short-term reliability risks

### Monthly Review
- SLO compliance for the month
- Error budget usage patterns
- SLO target adjustments
- Reliability improvement initiatives

### Quarterly Review
- SLO trends and patterns
- Customer impact analysis
- SLO target recalibration
- Infrastructure investment needs

## Reporting

### SLO Dashboard

The SLO dashboard should display:

1. **Current Status**
   - Real-time SLI values
   - SLO compliance status (✅/❌)
   - Error budget remaining

2. **Historical Trends**
   - 30-day SLO performance
   - Error budget burn rate
   - Incident annotations

3. **Detailed Metrics**
   - Per-route SLO breakdown
   - Per-region performance
   - Agent-specific impact

### Example Dashboard Query

```promql
# SLO Compliance Dashboard
- record: slo:availability:ratio
  expr: |
    sum(rate(sentinel_requests_total{status!~"5.."}[5m]))
    /
    sum(rate(sentinel_requests_total[5m]))

- record: slo:latency_p99:seconds
  expr: |
    histogram_quantile(0.99,
      sum(rate(sentinel_request_duration_seconds_bucket[5m])) by (le)
    )

- record: slo:error_budget_remaining:ratio
  expr: |
    1 - (
      (0.9995 - slo:availability:ratio) / 0.9995
    )
```

## SLO Implementation Checklist

### Initial Setup
- [ ] Deploy Prometheus with appropriate retention (90+ days)
- [ ] Configure recording rules for SLI calculation
- [ ] Create Grafana dashboards for SLO visualization
- [ ] Set up alerting rules in Prometheus/AlertManager
- [ ] Configure PagerDuty/Slack integrations
- [ ] Document runbooks for each alert

### Ongoing Operations
- [ ] Weekly SLO review meetings
- [ ] Monthly error budget reports
- [ ] Quarterly SLO calibration
- [ ] Annual SLO strategy review
- [ ] Continuous improvement based on incidents

## Customer-Facing SLA

While our internal SLO is 99.95%, we may offer different SLA tiers to customers:

### SLA Tiers

| Tier | Availability SLA | Latency SLA | Support Response |
|------|-----------------|-------------|------------------|
| **Enterprise** | 99.95% | P99 < 1s | 15 minutes |
| **Business** | 99.9% | P99 < 2s | 1 hour |
| **Standard** | 99.5% | Best effort | 24 hours |

### SLA Credits

| Monthly Uptime | Credit Percentage |
|----------------|-------------------|
| 99.95% - 100% | 0% |
| 99.0% - 99.95% | 10% |
| 95.0% - 99.0% | 25% |
| < 95.0% | 100% |

## Tools and Resources

### Monitoring Tools
- **Prometheus**: Metrics collection and storage
- **Grafana**: Visualization and dashboards
- **AlertManager**: Alert routing and silencing
- **PagerDuty**: On-call management
- **Slack**: Team notifications

### SLO Tools
- **Sloth**: SLO generator for Prometheus
- **OpenSLO**: SLO specification language
- **Pyrra**: SLO management and visualization

### References
- [Google SRE Book - SLO Chapter](https://sre.google/sre-book/service-level-objectives/)
- [The Site Reliability Workbook](https://sre.google/workbook/table-of-contents/)
- [Implementing SLOs](https://sre.google/workbook/implementing-slos/)

## Appendix: Example SLO Report

```markdown
# Sentinel SLO Report - January 2024

## Executive Summary
- Overall Availability: 99.96% ✅ (Target: 99.95%)
- P99 Latency: 312ms ✅ (Target: < 500ms)
- Error Budget Remaining: 74%

## Detailed Metrics
| Metric | Target | Actual | Status |
|--------|--------|--------|--------|
| Availability | 99.95% | 99.96% | ✅ |
| P50 Latency | < 50ms | 23ms | ✅ |
| P99 Latency | < 500ms | 312ms | ✅ |
| Error Rate | < 0.1% | 0.04% | ✅ |

## Incidents Impact
- Jan 5: 5-minute outage (-0.01% availability)
- Jan 12: Latency spike (-0.005% availability)
- Jan 20: WAF false positives (-0.002% availability)

## Action Items
- Improve WAF tuning to reduce false positives
- Add circuit breakers to problematic upstream
- Increase memory limits to prevent OOM

## Error Budget Status
- Budget at start: 21.6 minutes
- Budget consumed: 5.6 minutes (26%)
- Budget remaining: 16 minutes (74%)
- Projected end-of-month: 32% consumption ✅
```
