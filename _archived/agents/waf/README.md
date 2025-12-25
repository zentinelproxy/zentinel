# Sentinel WAF Agent

A production-grade Web Application Firewall (WAF) agent for the Sentinel reverse proxy platform, providing ModSecurity-based protection with OWASP Core Rule Set (CRS) support.

## Features

- **ModSecurity v3 Integration**: Full support for the industry-standard WAF engine
- **OWASP CRS Compatible**: Runs the latest Core Rule Set for comprehensive protection
- **High Performance**: Sub-2ms p99 latency with full inspection enabled
- **Flexible Exclusions**: Granular control over what to inspect and when
- **Audit Logging**: Comprehensive JSON-formatted audit trail
- **Hot Reload**: Update rules without restarting the agent
- **Bounded Resources**: Memory and CPU limits prevent resource exhaustion

## Prerequisites

### ModSecurity Installation

#### macOS
```bash
brew install modsecurity
```

#### Ubuntu/Debian
```bash
sudo apt-get update
sudo apt-get install libmodsecurity3 libmodsecurity-dev
```

#### RHEL/CentOS
```bash
sudo yum install modsecurity modsecurity-devel
```

#### Build from Source
```bash
git clone --depth 1 -b v3/master --single-branch https://github.com/SpiderLabs/ModSecurity
cd ModSecurity
./build.sh
./configure
make
sudo make install
```

### OWASP Core Rule Set

```bash
# Download latest CRS
wget https://github.com/coreruleset/coreruleset/archive/v4.0.0.tar.gz
tar -xzvf v4.0.0.tar.gz
sudo mv coreruleset-4.0.0 /usr/share/modsecurity-crs

# Set up configuration
cd /usr/share/modsecurity-crs
sudo cp crs-setup.conf.example crs-setup.conf
```

## Building

### With ModSecurity (Production)
```bash
cargo build --release -p sentinel-waf-agent
```

### Standalone Mode (Testing)
```bash
cargo build --release -p sentinel-waf-agent --features standalone
```

## Installation

```bash
# Install binary
sudo cp target/release/sentinel-waf-agent /usr/local/bin/

# Create directories
sudo mkdir -p /etc/sentinel /var/log/sentinel-waf /var/run/sentinel

# Install configuration
sudo cp config/waf/waf.yaml /etc/sentinel/

# Set up systemd service
sudo cp deploy/sentinel-waf.service /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl enable sentinel-waf
sudo systemctl start sentinel-waf
```

## Configuration

### Basic Configuration

```yaml
# /etc/sentinel/waf.yaml
engine:
  enabled: true
  detection_only: false  # Set to true for testing
  paranoia_level: 1      # 1-4, higher = more strict

rules:
  load_crs: true
  crs_path: /usr/share/modsecurity-crs

body_inspection:
  max_request_body_size: 10485760  # 10MB

audit:
  enabled: true
  log_dir: /var/log/sentinel-waf

listener:
  socket_path: /var/run/sentinel/waf.sock
```

### Security Levels

#### Level 1: Basic Protection (Recommended Start)
```yaml
engine:
  paranoia_level: 1
  anomaly_threshold: 10
```

#### Level 2: Balanced Protection
```yaml
engine:
  paranoia_level: 2
  anomaly_threshold: 7
```

#### Level 3: Strict Protection
```yaml
engine:
  paranoia_level: 3
  anomaly_threshold: 5
```

#### Level 4: Paranoid Mode
```yaml
engine:
  paranoia_level: 4
  anomaly_threshold: 3
```

### Exclusions

Exclude specific paths, IPs, or conditions from WAF inspection:

```yaml
exclusions:
  # Exclude health checks
  - name: "health-check"
    bypass_waf: true
    conditions:
      - type: path
        pattern: "/health"

  # Reduce false positives for admin network
  - name: "internal-network"
    exclude_rule_tags: ["attack-sqli", "attack-xss"]
    conditions:
      - type: client_ip
        value: "10.0.0.0/8"

  # Exclude file uploads from body limits
  - name: "file-upload"
    exclude_rule_ids: [200002]
    conditions:
      - type: path
        pattern: "^/api/upload"
        regex: true
      - type: method
        value: "POST"
```

## Integration with Sentinel Proxy

### Configure Agent in Proxy

```kdl
// sentinel-proxy.kdl
agent "waf-agent" {
    type "waf"
    transport "unix_socket" {
        path "/var/run/sentinel/waf.sock"
    }
    events ["request_headers" "request_body"]
    timeout-ms 100
    failure-mode "open"  // or "closed" for strict security
}

route "protected" {
    matches { path-prefix "/" }
    upstream "backend"
    agents ["waf-agent"]
}
```

## Monitoring

### Prometheus Metrics

The WAF agent exposes metrics on port 9094 by default:

```bash
curl http://localhost:9094/metrics
```

Key metrics:
- `waf_requests_total`: Total requests processed
- `waf_requests_blocked_total`: Requests blocked by WAF
- `waf_processing_duration_seconds`: Processing latency
- `waf_active_transactions`: Current active transactions
- `waf_rule_hits_total`: Hits per rule ID

### Audit Logs

Audit logs are written to `/var/log/sentinel-waf/` in JSON format:

```bash
# View recent blocks
tail -f /var/log/sentinel-waf/audit_*.json | jq '.action == "blocked"'

# Find top blocked IPs
cat /var/log/sentinel-waf/audit_*.json | jq -r '.client_ip' | sort | uniq -c | sort -rn

# Analyze specific rule hits
grep '"rule_id":941100' /var/log/sentinel-waf/audit_*.json | jq .
```

## Troubleshooting

### WAF Not Starting

1. Check ModSecurity installation:
```bash
ldconfig -p | grep modsecurity
```

2. Verify socket permissions:
```bash
ls -la /var/run/sentinel/
```

3. Check logs:
```bash
journalctl -u sentinel-waf -f
```

### False Positives

1. Enable detection-only mode:
```yaml
engine:
  detection_only: true
```

2. Analyze audit logs to identify problematic rules:
```bash
cat /var/log/sentinel-waf/audit_*.json | jq '.matched_rules'
```

3. Create targeted exclusions:
```yaml
exclusions:
  - name: "api-false-positive"
    exclude_rule_ids: [941100]  # Specific rule causing issues
    conditions:
      - type: path
        pattern: "/api/special-endpoint"
```

### High Latency

1. Reduce paranoia level:
```yaml
engine:
  paranoia_level: 1
```

2. Disable body inspection for large uploads:
```yaml
exclusions:
  - name: "large-uploads"
    bypass_waf: true
    conditions:
      - type: path
        pattern: "/upload"
      - type: header
        name: "Content-Length"
        value: "10485760"  # > 10MB
```

3. Increase worker threads:
```yaml
performance:
  worker_threads: 16
```

## Performance Tuning

### Memory Usage

Control memory usage with transaction limits:

```yaml
performance:
  max_concurrent_transactions: 5000  # Reduce for lower memory
  transaction_pool_size: 500

body_inspection:
  request_body_buffer_limit: 131072  # 128KB chunks
```

### CPU Usage

Optimize CPU usage:

```yaml
engine:
  pcre_jit: true  # Enable PCRE JIT compilation

performance:
  optimize_rules: true
  worker_threads: 8  # Match CPU cores
```

### Network Optimization

```yaml
listener:
  max_connections: 1000
  buffer_size: 65536  # 64KB
  connection_timeout_ms: 5000
```

## Testing

### Unit Tests
```bash
cargo test -p sentinel-waf-agent
```

### Integration Tests
```bash
./tests/test_waf.sh
```

### Load Testing
```bash
# Test with Apache Bench
ab -n 10000 -c 100 http://localhost:8080/

# Test with wrk
wrk -t12 -c400 -d30s http://localhost:8080/
```

### Security Testing
```bash
# Test SQL injection blocking
curl "http://localhost:8080/test?id=1' OR '1'='1"

# Test XSS blocking
curl -X POST http://localhost:8080/comment \
  -d "text=<script>alert('XSS')</script>"

# Test with OWASP ZAP
docker run -t owasp/zap2docker-stable zap-baseline.py \
  -t http://localhost:8080
```

## Development

### Building with Debug Symbols
```bash
cargo build -p sentinel-waf-agent
RUST_LOG=debug ./target/debug/sentinel-waf-agent
```

### Custom Rules

Add custom ModSecurity rules:

```yaml
rules:
  custom_rules:
    - |
      SecRule REQUEST_URI "@contains /admin" \
        "id:100001,\
        phase:1,\
        block,\
        msg:'Admin access attempted',\
        severity:'WARNING'"
```

### Extending the Agent

The WAF agent can be extended by modifying `src/main.rs`:

```rust
// Add custom processing logic
async fn custom_check(event: &RequestEvent) -> bool {
    // Custom security logic
    false
}
```

## License

MIT OR Apache-2.0

## Support

- GitHub Issues: https://github.com/raskell-io/sentinel/issues
- Documentation: https://sentinel.rs/docs/waf
- Security: security@sentinel.rs