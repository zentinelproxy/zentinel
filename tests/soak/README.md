# Zentinel Soak Testing

Extended-duration load tests (24-72 hours) to detect memory leaks and stability issues before production deployment.

## Quick Start

```bash
# Install dependencies
brew install oha jq  # or: cargo install oha

# Run a 1-hour quick soak test
./run-soak-test.sh --duration 1

# Run full 24-hour soak test
./run-soak-test.sh --duration 24

# Run 72-hour extended test (recommended before major releases)
./run-soak-test.sh --duration 72 --rps 200
```

## What It Tests

The soak test exercises Zentinel under sustained load to detect:

1. **Memory leaks** - Gradual memory growth that would eventually cause OOM
2. **Resource exhaustion** - File descriptor leaks, connection pool issues
3. **Performance degradation** - Latency increases over time
4. **Stability issues** - Crashes, hangs, or unexpected behavior

## How It Works

```
┌─────────────┐     ┌─────────────┐     ┌─────────────┐
│  Load Gen   │────▶│  Zentinel   │────▶│  Backend    │
│   (oha)     │     │   Proxy     │     │  (httpbin)  │
└─────────────┘     └─────────────┘     └─────────────┘
                           │
                           ▼
                    ┌─────────────┐
                    │   Memory    │
                    │  Monitor    │
                    └─────────────┘
```

1. **Backend** - Simple HTTP server returns test responses
2. **Zentinel** - Runs with production-like config
3. **Load Generator** - Sends sustained traffic (default: 100 RPS)
4. **Memory Monitor** - Samples RSS every 60 seconds
5. **Analyzer** - Detects leak patterns using linear regression

## Configuration

### Test Parameters

| Option | Default | Description |
|--------|---------|-------------|
| `--duration` | 24 | Test duration in hours |
| `--rps` | 100 | Requests per second |
| `--connections` | 10 | Concurrent connections |
| `--output` | ./results | Output directory |
| `--config` | soak-config.kdl | Zentinel config file |
| `--skip-build` | false | Skip cargo build |
| `--docker` | false | Run in Docker |

### Examples

```bash
# Quick validation (1 hour)
./run-soak-test.sh --duration 1 --rps 50

# Standard soak (24 hours)
./run-soak-test.sh --duration 24 --rps 100

# High-load soak (24 hours, 500 RPS)
./run-soak-test.sh --duration 24 --rps 500 --connections 50

# Extended soak (72 hours)
./run-soak-test.sh --duration 72 --rps 100

# Use pre-built binary
./run-soak-test.sh --skip-build --duration 24

# Run in Docker
./run-soak-test.sh --docker --duration 24
```

## Output

Results are saved to `./results/<timestamp>/`:

```
results/20241231_120000/
├── summary.txt           # Human-readable summary
├── analysis_report.json  # Machine-readable report
├── load_results.json     # Load test results (oha)
├── memory/
│   └── memory.csv        # Memory samples (timestamp, bytes, MB)
├── metrics/
│   ├── metrics_*.txt     # Prometheus metrics snapshots
├── logs/
│   ├── build.log         # Cargo build output
│   ├── zentinel.log      # Proxy logs
│   ├── backend.log       # Backend logs
│   └── load.log          # Load generator logs
```

## Analyzing Results

### Automatic Analysis

The test runner automatically analyzes results and prints a verdict:

```
Memory Analysis
---------------
Samples: 1440
Initial: 45 MB
Final: 48 MB
Growth: 3 MB (6.7%)

Leak Detection
--------------
STATUS: OK - No significant memory growth
```

### Manual Analysis

Use the Python analyzer for detailed analysis:

```bash
python3 analyze-results.py ./results/20241231_120000
```

Output:
```
Memory Statistics
----------------------------------------
Duration:        24.0 hours
Samples:         1440
Initial:         45 MB
Final:           48 MB
Growth Rate:     0.125 MB/hour
Total Growth:    3.0 MB (6.7%)
R² (trend fit):  0.234

Memory Chart
----------------------------------------
    48MB │        ▄▄▄▄▄▄▄▄▄▄▄█████████████████
    46MB │  ▄▄▄▄██████████████████████████████
    45MB │███████████████████████████████████
        └───────────────────────────────────
         Start                            End

Verdict
----------------------------------------
🟢 NO LEAK (confidence: 95%)
```

### Leak Detection Criteria

| Metric | Threshold | Meaning |
|--------|-----------|---------|
| Growth Rate | > 0.5 MB/hr | Potential slow leak |
| Total Growth | > 20% | Significant accumulation |
| R² | > 0.7 | Consistent linear growth |
| Trend Direction | 80%+ increasing | Monotonic growth pattern |

**Verdicts:**
- 🟢 **NO LEAK** - Memory stable, safe for production
- 🟡 **WARNING** - Elevated growth, investigate before production
- 🔴 **LEAK DETECTED** - Do not deploy, investigate immediately

## CI Integration

### Exit Codes

| Code | Meaning |
|------|---------|
| 0 | No leak detected |
| 1 | Warning (elevated growth) |
| 2 | Leak detected |

### GitHub Actions Example

```yaml
name: Soak Test

on:
  schedule:
    - cron: '0 0 * * 0'  # Weekly on Sunday

jobs:
  soak:
    runs-on: ubuntu-latest
    timeout-minutes: 1500  # 25 hours

    steps:
    - uses: actions/checkout@v4

    - name: Install dependencies
      run: |
        cargo install oha
        sudo apt-get install -y jq

    - name: Run soak test
      run: |
        cd tests/soak
        ./run-soak-test.sh --duration 24

    - name: Upload results
      if: always()
      uses: actions/upload-artifact@v4
      with:
        name: soak-results
        path: tests/soak/results/
```

## Troubleshooting

### Test Fails to Start

```bash
# Check if ports are in use
lsof -i :8080
lsof -i :8081
lsof -i :9090

# Kill any existing processes
pkill -f zentinel
pkill -f "python3 -m http.server"
```

### Memory Data Missing

```bash
# Check if Zentinel is running
ps aux | grep zentinel

# Check memory monitoring
tail -f results/*/memory/memory.csv
```

### Load Generator Errors

```bash
# Check if backend is responding
curl http://localhost:8081/health

# Check load generator logs
cat results/*/logs/load.log
```

## Best Practices

1. **Run on dedicated machine** - Avoid interference from other processes
2. **Use native builds** - Docker adds overhead (see ROADMAP.md benchmark notes)
3. **Monitor system resources** - Watch for CPU, disk, network saturation
4. **Run multiple durations** - 1h quick, 24h standard, 72h extended
5. **Compare baselines** - Keep results from previous versions
6. **Investigate warnings** - Don't ignore elevated growth patterns

## Memory Leak Investigation

If a leak is detected:

1. **Enable debug logging** - Set `logging { level "debug" }` in config
2. **Run with profiling** - `MALLOC_CONF=prof:true ./zentinel`
3. **Check rate limiter cleanup** - Idle entries should be cleaned up
4. **Check connection pools** - Connections should be recycled
5. **Check cache eviction** - Caches should respect size limits
6. **Review recent changes** - Compare against last known-good version

## See Also

- [ROADMAP.md](../../.claude/ROADMAP.md) - Production readiness checklist
- [tests/README.md](../README.md) - Integration test documentation
- [Benchmark Results](../../.claude/ROADMAP.md#benchmark-results) - Performance baseline
