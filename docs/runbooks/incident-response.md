# Sentinel Incident Response Runbook

## Overview

This runbook provides step-by-step procedures for handling common incidents with the Sentinel reverse proxy platform. Each procedure includes detection, diagnosis, mitigation, and recovery steps.

## Quick Reference

| Symptom | Likely Cause | Page |
|---------|-------------|------|
| High latency (>500ms p99) | Agent timeout, upstream slowness | [High Latency](#high-latency) |
| 5xx errors spike | Upstream failure, OOM | [Server Errors](#server-errors) |
| Connection refused | Service down, port blocked | [Connection Issues](#connection-issues) |
| WAF blocking legitimate traffic | False positives | [WAF Issues](#waf-issues) |
| Memory usage increasing | Memory leak, traffic spike | [Memory Issues](#memory-issues) |
| Circuit breaker open | Agent failures | [Circuit Breaker](#circuit-breaker-issues) |

## Incident Severity Levels

- **P0 (Critical)**: Complete service outage, data loss risk
- **P1 (High)**: Significant degradation, >10% errors
- **P2 (Medium)**: Partial degradation, <10% errors
- **P3 (Low)**: Minor issues, no user impact

## Common Incidents

### High Latency

**Detection**:
- Alert: `SentinelHighLatency` firing
- P99 latency > 500ms for 10+ minutes
- User complaints about slowness

**Diagnosis**:
1. Check proxy metrics:
```bash
curl -s http://sentinel-proxy:9090/metrics | grep sentinel_request_duration_seconds
```

2. Identify slow component:
```bash
# Check agent latencies
curl -s http://sentinel-proxy:9090/metrics | grep agent_request_duration

# Check upstream latencies  
curl -s http://sentinel-proxy:9090/metrics | grep upstream_request_duration
```

3. Check logs for timeouts:
```bash
kubectl logs -n sentinel deployment/sentinel-proxy --tail=100 | grep -i timeout
```

**Mitigation**:
1. If agent is slow:
```bash
# Temporarily disable slow agent
kubectl patch configmap sentinel-proxy-config -n sentinel --type json -p='[{"op": "remove", "path": "/data/agents/waf-agent"}]'
kubectl rollout restart deployment/sentinel-proxy -n sentinel
```

2. If upstream is slow:
```bash
# Increase timeout temporarily
kubectl set env deployment/sentinel-proxy -n sentinel UPSTREAM_TIMEOUT_MS=10000
```

3. Scale up if under load:
```bash
kubectl scale deployment/sentinel-proxy -n sentinel --replicas=10
```

**Recovery**:
1. Fix root cause (optimize agent, fix upstream)
2. Restore original configuration
3. Verify metrics return to normal
4. Document incident

### Server Errors

**Detection**:
- Alert: `SentinelHighErrorRate` firing
- 5xx errors > 5% for 5+ minutes
- Multiple user reports

**Diagnosis**:
1. Check error distribution:
```bash
# By status code
curl -s http://sentinel-proxy:9090/metrics | grep 'sentinel_requests_total{status="5'

# Recent errors in logs
kubectl logs -n sentinel deployment/sentinel-proxy --tail=500 | grep -E 'status=5[0-9]{2}'
```

2. Check resource usage:
```bash
# CPU and Memory
kubectl top pods -n sentinel

# Detailed resource metrics
kubectl describe pod -n sentinel -l app=sentinel-proxy
```

3. Check upstream health:
```bash
curl -s http://sentinel-proxy:9090/metrics | grep upstream_healthy
```

**Mitigation**:
1. If OOM (Out of Memory):
```bash
# Increase memory limit
kubectl set resources deployment/sentinel-proxy -n sentinel --limits=memory=4Gi

# Restart pods
kubectl rollout restart deployment/sentinel-proxy -n sentinel
```

2. If upstream is down:
```bash
# Failover to backup upstream
kubectl patch configmap sentinel-proxy-config -n sentinel --type json \
  -p='[{"op": "replace", "path": "/data/upstream/primary", "value": "backup.example.com:80"}]'
kubectl rollout restart deployment/sentinel-proxy -n sentinel
```

3. Enable circuit breaker:
```bash
kubectl patch configmap sentinel-proxy-config -n sentinel --type merge \
  -p='{"data":{"circuit_breaker_enabled":"true"}}'
```

**Recovery**:
1. Identify and fix root cause
2. Restore normal configuration
3. Reset circuit breakers if needed
4. Verify error rate returns to baseline

### Connection Issues

**Detection**:
- Cannot connect to proxy
- "Connection refused" errors
- Health checks failing

**Diagnosis**:
1. Check pod status:
```bash
kubectl get pods -n sentinel
kubectl describe pod -n sentinel -l app=sentinel-proxy
```

2. Check service endpoints:
```bash
kubectl get endpoints -n sentinel
kubectl get svc -n sentinel
```

3. Test connectivity:
```bash
# From within cluster
kubectl run test-curl --image=curlimages/curl --rm -it -- curl http://sentinel-proxy:8080/health

# Port forwarding for local test
kubectl port-forward -n sentinel svc/sentinel-proxy 8080:8080
curl http://localhost:8080/health
```

**Mitigation**:
1. If pods are crashing:
```bash
# Check logs for crash reason
kubectl logs -n sentinel deployment/sentinel-proxy --previous

# Increase resource limits if needed
kubectl set resources deployment/sentinel-proxy -n sentinel \
  --requests=cpu=500m,memory=512Mi \
  --limits=cpu=2,memory=2Gi
```

2. If service misconfigured:
```bash
# Recreate service
kubectl delete svc sentinel-proxy -n sentinel
kubectl apply -f deploy/kubernetes/service.yaml
```

3. Emergency bypass:
```bash
# Direct port-forward for debugging
kubectl port-forward -n sentinel deployment/sentinel-proxy 8080:8080
```

**Recovery**:
1. Fix underlying issue
2. Ensure all pods are running
3. Verify service endpoints
4. Test end-to-end connectivity

### WAF Issues

**Detection**:
- Legitimate requests blocked (403 responses)
- Alert: `SentinelWAFHighBlockRate`
- User reports of access denied

**Diagnosis**:
1. Check WAF metrics:
```bash
curl -s http://waf-agent:9094/metrics | grep waf_requests_blocked
```

2. Review audit logs:
```bash
# Recent blocks
kubectl logs -n sentinel deployment/sentinel-waf --tail=100 | jq 'select(.action=="blocked")'

# Find patterns
kubectl logs -n sentinel deployment/sentinel-waf --tail=1000 | \
  jq -r 'select(.action=="blocked") | .rule_id' | sort | uniq -c | sort -rn
```

3. Identify false positives:
```bash
# Check specific rule
kubectl logs -n sentinel deployment/sentinel-waf | \
  jq 'select(.rule_id=="941100")'
```

**Mitigation**:
1. Enable detection-only mode:
```bash
kubectl patch configmap sentinel-waf-config -n sentinel --type merge \
  -p='{"data":{"engine.detection_only":"true"}}'
kubectl rollout restart deployment/sentinel-waf -n sentinel
```

2. Add exclusion for false positive:
```bash
# Edit WAF config to add exclusion
kubectl edit configmap sentinel-waf-config -n sentinel

# Add under exclusions:
# - name: "api-false-positive"
#   exclude_rule_ids: [941100]
#   conditions:
#     - type: path
#       pattern: "/api/special"
```

3. Lower paranoia level:
```bash
kubectl patch configmap sentinel-waf-config -n sentinel --type merge \
  -p='{"data":{"engine.paranoia_level":"1"}}'
```

**Recovery**:
1. Analyze false positives
2. Create targeted exclusions
3. Re-enable blocking mode
4. Monitor for continued issues

### Memory Issues

**Detection**:
- Alert: `SentinelHighMemoryUsage`
- OOMKilled events
- Increasing memory trend

**Diagnosis**:
1. Check memory usage:
```bash
# Current usage
kubectl top pods -n sentinel

# Historical trend
curl -s http://prometheus:9090/api/v1/query_range \
  -d 'query=container_memory_usage_bytes{pod=~"sentinel-.*"}' \
  -d 'start=1h' -d 'end=now' -d 'step=1m'
```

2. Identify memory leaks:
```bash
# Check goroutines (for Go components)
curl http://sentinel-proxy:9090/debug/pprof/goroutine

# Heap profile
curl http://sentinel-proxy:9090/debug/pprof/heap > heap.prof
```

3. Check for large requests:
```bash
kubectl logs -n sentinel deployment/sentinel-proxy | \
  grep -i "content-length" | awk '{print $NF}' | sort -rn | head
```

**Mitigation**:
1. Increase memory limits:
```bash
kubectl set resources deployment/sentinel-proxy -n sentinel --limits=memory=4Gi
```

2. Enable request size limits:
```bash
kubectl patch configmap sentinel-proxy-config -n sentinel --type merge \
  -p='{"data":{"max_request_body_size":"10485760"}}'
```

3. Restart pods to clear memory:
```bash
kubectl rollout restart deployment/sentinel-proxy -n sentinel
```

4. Scale horizontally:
```bash
kubectl scale deployment/sentinel-proxy -n sentinel --replicas=10
```

**Recovery**:
1. Identify root cause (leak, large requests)
2. Apply permanent fix
3. Restore normal resource limits
4. Monitor memory usage

### Circuit Breaker Issues

**Detection**:
- Agent calls failing
- Circuit breaker metrics showing "open"
- Degraded functionality

**Diagnosis**:
1. Check circuit breaker status:
```bash
curl -s http://sentinel-proxy:9090/metrics | grep circuit_breaker_state
```

2. Review agent failures:
```bash
kubectl logs -n sentinel deployment/sentinel-proxy | grep -i "circuit.*open"
```

3. Test agent directly:
```bash
# Port-forward to agent
kubectl port-forward -n sentinel deployment/sentinel-waf 9094:9094
curl http://localhost:9094/health
```

**Mitigation**:
1. Reset circuit breaker:
```bash
# Send reset signal
curl -X POST http://sentinel-proxy:9090/admin/circuit-breaker/reset
```

2. Increase failure threshold:
```bash
kubectl patch configmap sentinel-proxy-config -n sentinel --type merge \
  -p='{"data":{"circuit_breaker.failure_threshold":"10"}}'
```

3. Fix agent issues:
```bash
# Restart problematic agent
kubectl rollout restart deployment/sentinel-waf -n sentinel

# Check agent logs
kubectl logs -n sentinel deployment/sentinel-waf --tail=100
```

**Recovery**:
1. Ensure agent is healthy
2. Monitor circuit breaker metrics
3. Adjust thresholds if needed
4. Document pattern of failures

## Monitoring Commands

### Health Checks
```bash
# Proxy health
curl http://sentinel-proxy:9090/health

# Agent health
curl http://sentinel-waf:9094/health
curl http://sentinel-ratelimit:9092/health

# Kubernetes checks
kubectl get pods -n sentinel
kubectl get events -n sentinel --sort-by='.lastTimestamp'
```

### Metrics Queries
```bash
# Request rate
curl -s http://prometheus:9090/api/v1/query -d 'query=rate(sentinel_requests_total[5m])'

# Error rate
curl -s http://prometheus:9090/api/v1/query -d 'query=rate(sentinel_requests_total{status=~"5.."}[5m])'

# P99 latency
curl -s http://prometheus:9090/api/v1/query -d 'query=histogram_quantile(0.99, rate(sentinel_request_duration_seconds_bucket[5m]))'
```

### Log Analysis
```bash
# Recent errors
kubectl logs -n sentinel deployment/sentinel-proxy --tail=100 | jq 'select(.level=="error")'

# Request patterns
kubectl logs -n sentinel deployment/sentinel-proxy --tail=1000 | \
  jq -r '.path' | sort | uniq -c | sort -rn | head

# Slow requests
kubectl logs -n sentinel deployment/sentinel-proxy | \
  jq 'select(.duration_ms > 1000)'
```

## Recovery Procedures

### Full Service Restart
```bash
#!/bin/bash
# Full restart procedure

NAMESPACE=sentinel

echo "Starting full service restart..."

# 1. Scale down
kubectl scale deployment --all -n $NAMESPACE --replicas=0

# 2. Wait for pods to terminate
kubectl wait --for=delete pod -l app=sentinel -n $NAMESPACE --timeout=60s

# 3. Clear persistent data if needed
# kubectl delete pvc --all -n $NAMESPACE

# 4. Scale up proxy first
kubectl scale deployment/sentinel-proxy -n $NAMESPACE --replicas=3
kubectl wait --for=condition=available deployment/sentinel-proxy -n $NAMESPACE --timeout=120s

# 5. Scale up agents
kubectl scale deployment/sentinel-waf -n $NAMESPACE --replicas=2
kubectl scale deployment/sentinel-ratelimit -n $NAMESPACE --replicas=2

# 6. Wait for all pods
kubectl wait --for=condition=ready pod -l app=sentinel -n $NAMESPACE --timeout=120s

# 7. Verify health
sleep 10
curl -f http://sentinel-proxy:9090/health || exit 1

echo "Service restart complete"
```

### Configuration Rollback
```bash
#!/bin/bash
# Rollback configuration to previous version

NAMESPACE=sentinel

# Get previous configuration
kubectl rollout history deployment/sentinel-proxy -n $NAMESPACE

# Rollback to previous
kubectl rollout undo deployment/sentinel-proxy -n $NAMESPACE

# Wait for rollout
kubectl rollout status deployment/sentinel-proxy -n $NAMESPACE

# Verify
kubectl get pods -n $NAMESPACE
```

### Emergency Bypass
```bash
#!/bin/bash
# Emergency bypass - route traffic directly to upstream

NAMESPACE=sentinel

# Create emergency service pointing to upstream
cat <<EOF | kubectl apply -f -
apiVersion: v1
kind: Service
metadata:
  name: emergency-bypass
  namespace: $NAMESPACE
spec:
  type: ExternalName
  externalName: upstream.example.com
  ports:
  - port: 80
    targetPort: 80
EOF

# Update ingress to use bypass
kubectl patch ingress sentinel -n $NAMESPACE --type json \
  -p='[{"op": "replace", "path": "/spec/rules/0/http/paths/0/backend/service/name", "value": "emergency-bypass"}]'

echo "Emergency bypass activated - traffic going directly to upstream"
```

## Escalation

### Escalation Path
1. **L1 Support**: Initial triage, basic troubleshooting
2. **L2 Operations**: Advanced troubleshooting, mitigation
3. **L3 Engineering**: Root cause analysis, code fixes
4. **On-call Lead**: Coordination, external communication

### When to Escalate
- P0/P1 incidents after 30 minutes
- Unable to identify root cause
- Requires code changes
- Data loss risk
- Security incident

### Escalation Contacts
- On-call: Check PagerDuty schedule
- Engineering: #sentinel-engineering Slack
- Security: security@company.com
- Leadership: For P0 incidents only

## Post-Incident

### Required Actions
1. Update incident ticket with:
   - Timeline of events
   - Actions taken
   - Root cause
   - Impact assessment

2. Schedule post-mortem for:
   - P0/P1 incidents
   - Repeated incidents
   - Near-miss events

3. Update runbook with:
   - New procedures learned
   - Additional diagnostic steps
   - Automation opportunities

### Post-Mortem Template
```markdown
## Incident Post-Mortem

**Incident ID**: INC-XXXX
**Date**: YYYY-MM-DD
**Duration**: XX minutes
**Severity**: P0/P1/P2/P3

### Summary
Brief description of what happened.

### Timeline
- HH:MM - Event started
- HH:MM - Alert fired
- HH:MM - Investigation began
- HH:MM - Root cause identified
- HH:MM - Mitigation applied
- HH:MM - Service restored

### Root Cause
Technical explanation of why it happened.

### Impact
- Users affected: XXX
- Requests failed: XXX
- Revenue impact: $XXX

### What Went Well
- Quick detection
- Effective mitigation

### What Could Be Improved
- Alert tuning needed
- Documentation gaps

### Action Items
- [ ] Fix root cause (owner: @person, due: date)
- [ ] Improve monitoring (owner: @person, due: date)
- [ ] Update runbook (owner: @person, due: date)
```

## Appendix

### Useful Aliases
```bash
# Add to ~/.bashrc
alias kc='kubectl'
alias kcn='kubectl -n sentinel'
alias kclogs='kubectl logs -n sentinel'
alias kcpods='kubectl get pods -n sentinel'
alias sentinel-health='curl -s http://localhost:9090/health | jq .'
alias sentinel-metrics='curl -s http://localhost:9090/metrics'
```

### Emergency Contacts
- Cloudflare Status: https://www.cloudflarestatus.com/
- AWS Status: https://status.aws.amazon.com/
- GCP Status: https://status.cloud.google.com/
- Azure Status: https://status.azure.com/

### Documentation Links
- Sentinel Docs: https://sentinel.rs/docs
- Prometheus Queries: https://prometheus.io/docs/prometheus/latest/querying/
- Kubernetes Troubleshooting: https://kubernetes.io/docs/tasks/debug/
- ModSecurity Rules: https://coreruleset.org/docs/