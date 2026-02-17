#!/usr/bin/env python3
"""
Zentinel Soak Test Results Analyzer

Analyzes memory usage data from soak tests to detect memory leaks
using statistical methods.

Usage:
    python3 analyze-results.py <results_dir>
    python3 analyze-results.py ./results/20241231_120000

Output:
    - Memory growth analysis
    - Trend detection using linear regression
    - Visualization (if matplotlib available)
    - JSON report for CI integration
"""

import sys
import os
import json
import csv
from datetime import datetime
from pathlib import Path
from typing import List, Tuple, Optional
import statistics

def parse_memory_csv(filepath: str) -> List[Tuple[datetime, int, int]]:
    """Parse memory.csv and return list of (timestamp, bytes, mb) tuples."""
    data = []
    with open(filepath, 'r') as f:
        reader = csv.DictReader(f)
        for row in reader:
            try:
                ts = datetime.strptime(row['timestamp'], '%Y-%m-%d %H:%M:%S')
                mem_bytes = int(row['memory_bytes'])
                mem_mb = int(row['memory_mb'])
                data.append((ts, mem_bytes, mem_mb))
            except (ValueError, KeyError) as e:
                continue
    return data

def linear_regression(x: List[float], y: List[float]) -> Tuple[float, float]:
    """Simple linear regression returning (slope, intercept)."""
    n = len(x)
    if n < 2:
        return 0.0, 0.0

    sum_x = sum(x)
    sum_y = sum(y)
    sum_xy = sum(xi * yi for xi, yi in zip(x, y))
    sum_xx = sum(xi * xi for xi in x)

    denom = n * sum_xx - sum_x * sum_x
    if denom == 0:
        return 0.0, sum_y / n

    slope = (n * sum_xy - sum_x * sum_y) / denom
    intercept = (sum_y - slope * sum_x) / n

    return slope, intercept

def calculate_r_squared(x: List[float], y: List[float], slope: float, intercept: float) -> float:
    """Calculate R-squared value for linear fit."""
    if len(y) < 2:
        return 0.0

    y_mean = statistics.mean(y)
    ss_tot = sum((yi - y_mean) ** 2 for yi in y)
    ss_res = sum((yi - (slope * xi + intercept)) ** 2 for xi, yi in zip(x, y))

    if ss_tot == 0:
        return 1.0

    return 1 - (ss_res / ss_tot)

def detect_leak(data: List[Tuple[datetime, int, int]]) -> dict:
    """
    Analyze memory data to detect potential leaks.

    Returns a dict with:
    - leak_detected: bool
    - confidence: float (0-1)
    - growth_rate_mb_per_hour: float
    - analysis: str
    """
    if len(data) < 10:
        return {
            'leak_detected': False,
            'confidence': 0.0,
            'growth_rate_mb_per_hour': 0.0,
            'analysis': 'Insufficient data points for analysis'
        }

    # Convert timestamps to hours from start
    start_time = data[0][0]
    x = [(d[0] - start_time).total_seconds() / 3600 for d in data]  # hours
    y = [d[2] for d in data]  # MB

    # Calculate statistics
    mem_min = min(y)
    mem_max = max(y)
    mem_mean = statistics.mean(y)
    mem_stdev = statistics.stdev(y) if len(y) > 1 else 0

    # Linear regression to find trend
    slope, intercept = linear_regression(x, y)
    r_squared = calculate_r_squared(x, y, slope, intercept)

    # Calculate growth
    duration_hours = x[-1] if x else 0
    total_growth_mb = y[-1] - y[0] if y else 0
    growth_percent = (total_growth_mb / y[0] * 100) if y[0] > 0 else 0

    # Leak detection heuristics
    # 1. Positive slope with high R-squared indicates consistent growth
    # 2. Growth rate > 1 MB/hour is suspicious
    # 3. Total growth > 20% over test duration is suspicious

    leak_score = 0.0
    reasons = []

    # Check slope
    if slope > 0.5:  # Growing > 0.5 MB/hour
        leak_score += 0.3
        reasons.append(f"Positive memory trend: {slope:.2f} MB/hour")

    # Check R-squared (how well data fits a line)
    if r_squared > 0.7 and slope > 0:
        leak_score += 0.3
        reasons.append(f"Consistent growth pattern (R²={r_squared:.2f})")

    # Check total growth
    if growth_percent > 20:
        leak_score += 0.4
        reasons.append(f"High total growth: {growth_percent:.1f}%")
    elif growth_percent > 10:
        leak_score += 0.2
        reasons.append(f"Moderate growth: {growth_percent:.1f}%")

    # Check for consistent increases (monotonic trend)
    increasing_count = sum(1 for i in range(1, len(y)) if y[i] > y[i-1])
    increasing_ratio = increasing_count / (len(y) - 1) if len(y) > 1 else 0
    if increasing_ratio > 0.8:
        leak_score += 0.2
        reasons.append(f"Mostly increasing: {increasing_ratio*100:.0f}% of samples")

    leak_detected = leak_score >= 0.5

    if leak_detected:
        analysis = "POTENTIAL MEMORY LEAK DETECTED. " + "; ".join(reasons)
    elif leak_score >= 0.3:
        analysis = "WARNING: Elevated memory usage patterns. " + "; ".join(reasons)
    else:
        analysis = "No significant memory leak detected. Memory usage appears stable."

    return {
        'leak_detected': leak_detected,
        'confidence': min(leak_score, 1.0),
        'growth_rate_mb_per_hour': slope,
        'total_growth_mb': total_growth_mb,
        'total_growth_percent': growth_percent,
        'r_squared': r_squared,
        'duration_hours': duration_hours,
        'samples': len(data),
        'memory_min_mb': mem_min,
        'memory_max_mb': mem_max,
        'memory_mean_mb': mem_mean,
        'memory_stdev_mb': mem_stdev,
        'analysis': analysis,
        'reasons': reasons
    }

def generate_ascii_chart(data: List[Tuple[datetime, int, int]], width: int = 60, height: int = 15) -> str:
    """Generate a simple ASCII chart of memory usage."""
    if len(data) < 2:
        return "Insufficient data for chart"

    y_values = [d[2] for d in data]
    y_min = min(y_values)
    y_max = max(y_values)
    y_range = y_max - y_min or 1

    # Sample data to fit width
    step = max(1, len(y_values) // width)
    sampled = y_values[::step][:width]

    chart_lines = []

    # Generate chart
    for row in range(height - 1, -1, -1):
        threshold = y_min + (row / (height - 1)) * y_range
        line = ""
        for val in sampled:
            if val >= threshold:
                line += "█"
            else:
                line += " "

        # Add Y-axis label
        if row == height - 1:
            label = f"{y_max:>6}MB │"
        elif row == 0:
            label = f"{y_min:>6}MB │"
        elif row == height // 2:
            mid = (y_min + y_max) / 2
            label = f"{mid:>6.0f}MB │"
        else:
            label = "        │"

        chart_lines.append(label + line)

    # Add X-axis
    chart_lines.append("        └" + "─" * len(sampled))
    chart_lines.append(f"         Start{' ' * (len(sampled) - 10)}End")

    return "\n".join(chart_lines)

def main():
    if len(sys.argv) < 2:
        print(__doc__)
        sys.exit(1)

    results_dir = Path(sys.argv[1])

    if not results_dir.exists():
        print(f"Error: Results directory not found: {results_dir}")
        sys.exit(1)

    memory_file = results_dir / "memory" / "memory.csv"

    if not memory_file.exists():
        print(f"Error: Memory data not found: {memory_file}")
        sys.exit(1)

    print("=" * 60)
    print("     Zentinel Soak Test Analysis")
    print("=" * 60)
    print()

    # Parse data
    print("Loading memory data...")
    data = parse_memory_csv(str(memory_file))
    print(f"Loaded {len(data)} samples")
    print()

    if len(data) < 2:
        print("Error: Insufficient data for analysis")
        sys.exit(1)

    # Analyze
    print("Analyzing memory patterns...")
    results = detect_leak(data)

    # Print results
    print()
    print("Memory Statistics")
    print("-" * 40)
    print(f"Duration:        {results['duration_hours']:.1f} hours")
    print(f"Samples:         {results['samples']}")
    print(f"Initial:         {data[0][2]} MB")
    print(f"Final:           {data[-1][2]} MB")
    print(f"Min:             {results['memory_min_mb']} MB")
    print(f"Max:             {results['memory_max_mb']} MB")
    print(f"Mean:            {results['memory_mean_mb']:.1f} MB")
    print(f"Std Dev:         {results['memory_stdev_mb']:.1f} MB")
    print()

    print("Trend Analysis")
    print("-" * 40)
    print(f"Growth Rate:     {results['growth_rate_mb_per_hour']:.3f} MB/hour")
    print(f"Total Growth:    {results['total_growth_mb']:.1f} MB ({results['total_growth_percent']:.1f}%)")
    print(f"R² (trend fit):  {results['r_squared']:.3f}")
    print()

    print("Memory Chart")
    print("-" * 40)
    print(generate_ascii_chart(data))
    print()

    print("Verdict")
    print("-" * 40)
    if results['leak_detected']:
        print(f"🔴 LEAK DETECTED (confidence: {results['confidence']*100:.0f}%)")
    elif results['confidence'] >= 0.3:
        print(f"🟡 WARNING (confidence: {results['confidence']*100:.0f}%)")
    else:
        print(f"🟢 NO LEAK (confidence: {(1-results['confidence'])*100:.0f}%)")
    print()
    print(results['analysis'])
    print()

    if results['reasons']:
        print("Details:")
        for reason in results['reasons']:
            print(f"  - {reason}")
        print()

    # Save JSON report
    report_file = results_dir / "analysis_report.json"
    with open(report_file, 'w') as f:
        json.dump(results, f, indent=2, default=str)
    print(f"Report saved to: {report_file}")

    # Exit with error code if leak detected
    if results['leak_detected']:
        sys.exit(2)
    elif results['confidence'] >= 0.3:
        sys.exit(1)
    else:
        sys.exit(0)

if __name__ == '__main__':
    main()
