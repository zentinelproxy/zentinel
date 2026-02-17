#!/usr/bin/env python3
"""
Zentinel Chaos Test Results Analyzer

Analyzes chaos test results and generates a comprehensive report.
Parses logs, metrics, and chaos events to provide insights.

Usage:
    python analyze-chaos-results.py <results_dir>
    python analyze-chaos-results.py results/20240101_120000

Exit codes:
    0 - All tests passed
    1 - Some tests failed
    2 - Analysis error
"""

import argparse
import json
import os
import re
import sys
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from typing import Optional


@dataclass
class ScenarioResult:
    """Result of a single test scenario."""
    name: str
    status: str  # passed, failed, unknown
    tests_run: int = 0
    tests_passed: int = 0
    tests_failed: int = 0
    duration_secs: float = 0.0
    chaos_events: list = None
    errors: list = None

    def __post_init__(self):
        if self.chaos_events is None:
            self.chaos_events = []
        if self.errors is None:
            self.errors = []


@dataclass
class ChaosEvent:
    """A chaos injection or restoration event."""
    timestamp: str
    event_type: str
    target: str
    details: str = ""


class ChaosResultsAnalyzer:
    """Analyzer for chaos test results."""

    def __init__(self, results_dir: str):
        self.results_dir = Path(results_dir)
        self.scenarios: list[ScenarioResult] = []
        self.chaos_events: list[ChaosEvent] = []
        self.metrics: dict = {}
        self.summary: dict = {}

    def analyze(self) -> bool:
        """Run full analysis. Returns True if all tests passed."""
        print(f"Analyzing results in: {self.results_dir}")
        print()

        # Load summary.json if exists
        self._load_summary()

        # Parse chaos events log
        self._parse_chaos_events()

        # Parse scenario logs
        self._parse_scenario_logs()

        # Parse final metrics
        self._parse_metrics()

        # Generate report
        self._generate_report()

        # Return success status
        return all(s.status == "passed" for s in self.scenarios)

    def _load_summary(self):
        """Load summary.json if it exists."""
        summary_path = self.results_dir / "summary.json"
        if summary_path.exists():
            with open(summary_path) as f:
                self.summary = json.load(f)
            print(f"Loaded summary: {self.summary.get('tests', {})}")

    def _parse_chaos_events(self):
        """Parse chaos-events.log for injection timeline."""
        events_path = self.results_dir / "chaos-events.log"
        if not events_path.exists():
            print("No chaos events log found")
            return

        with open(events_path) as f:
            for line in f:
                parts = line.strip().split(maxsplit=3)
                if len(parts) >= 3:
                    event = ChaosEvent(
                        timestamp=parts[0],
                        event_type=parts[1],
                        target=parts[2],
                        details=parts[3] if len(parts) > 3 else ""
                    )
                    self.chaos_events.append(event)

        print(f"Parsed {len(self.chaos_events)} chaos events")

    def _parse_scenario_logs(self):
        """Parse individual scenario log files."""
        logs_dir = self.results_dir / "logs"
        if not logs_dir.exists():
            print("No logs directory found")
            return

        for log_file in sorted(logs_dir.glob("*.log")):
            if log_file.name in ["proxy.log", "echo.log", "backend-primary.log", "backend-secondary.log"]:
                continue  # Skip container logs

            scenario = self._parse_scenario_log(log_file)
            if scenario:
                self.scenarios.append(scenario)

        print(f"Parsed {len(self.scenarios)} scenario logs")

    def _parse_scenario_log(self, log_path: Path) -> Optional[ScenarioResult]:
        """Parse a single scenario log file."""
        name = log_path.stem.replace("test_", "")
        result = ScenarioResult(name=name, status="unknown")

        with open(log_path) as f:
            content = f.read()

        # Extract test counts from summary
        run_match = re.search(r"Total:\s+(\d+)", content)
        passed_match = re.search(r"Passed:\s+.*?(\d+)", content)
        failed_match = re.search(r"Failed:\s+.*?(\d+)", content)

        if run_match:
            result.tests_run = int(run_match.group(1))
        if passed_match:
            result.tests_passed = int(passed_match.group(1))
        if failed_match:
            result.tests_failed = int(failed_match.group(1))

        # Determine overall status
        if "ALL TESTS PASSED" in content:
            result.status = "passed"
        elif "SOME TESTS FAILED" in content:
            result.status = "failed"
        elif result.tests_failed > 0:
            result.status = "failed"
        elif result.tests_passed > 0:
            result.status = "passed"

        # Extract failure messages
        for line in content.split("\n"):
            if "[FAIL]" in line:
                result.errors.append(line.strip())

        return result

    def _parse_metrics(self):
        """Parse final metrics snapshot."""
        metrics_path = self.results_dir / "metrics" / "final.txt"
        if not metrics_path.exists():
            print("No final metrics found")
            return

        with open(metrics_path) as f:
            for line in f:
                if line.startswith("#") or not line.strip():
                    continue

                # Parse Prometheus format: metric_name{labels} value
                match = re.match(r"(\w+)(\{[^}]+\})?\s+([\d.e+-]+)", line)
                if match:
                    metric_name = match.group(1)
                    labels = match.group(2) or ""
                    value = float(match.group(3))

                    key = f"{metric_name}{labels}"
                    self.metrics[key] = value

        print(f"Parsed {len(self.metrics)} metric values")

    def _generate_report(self):
        """Generate and print the analysis report."""
        print()
        print("=" * 60)
        print("CHAOS TEST ANALYSIS REPORT")
        print("=" * 60)
        print()

        # Overall summary
        total_scenarios = len(self.scenarios)
        passed_scenarios = sum(1 for s in self.scenarios if s.status == "passed")
        failed_scenarios = sum(1 for s in self.scenarios if s.status == "failed")

        total_tests = sum(s.tests_run for s in self.scenarios)
        passed_tests = sum(s.tests_passed for s in self.scenarios)
        failed_tests = sum(s.tests_failed for s in self.scenarios)

        print("SUMMARY")
        print("-" * 40)
        print(f"Scenarios: {passed_scenarios}/{total_scenarios} passed")
        print(f"Tests:     {passed_tests}/{total_tests} passed")
        print()

        # Scenario breakdown
        print("SCENARIO RESULTS")
        print("-" * 40)
        for scenario in self.scenarios:
            status_icon = "✓" if scenario.status == "passed" else "✗"
            print(f"  {status_icon} {scenario.name}")
            print(f"    Tests: {scenario.tests_passed}/{scenario.tests_run} passed")
            if scenario.errors:
                for error in scenario.errors[:3]:  # Show first 3 errors
                    print(f"    ERROR: {error}")
        print()

        # Chaos event summary
        if self.chaos_events:
            print("CHAOS EVENTS SUMMARY")
            print("-" * 40)
            event_counts = {}
            for event in self.chaos_events:
                event_counts[event.event_type] = event_counts.get(event.event_type, 0) + 1

            for event_type, count in sorted(event_counts.items()):
                print(f"  {event_type}: {count}")
            print()

        # Key metrics
        print("KEY METRICS")
        print("-" * 40)
        self._print_metric("Agent failures", "zentinel_agent_failures_total")
        self._print_metric("Agent timeouts", "zentinel_agent_timeouts_total")
        self._print_metric("Agent bypasses (fail-open)", "zentinel_agent_bypasses_total")
        self._print_metric("Circuit breaker opens", "zentinel_agent_circuit_breaker_opens_total")
        self._print_metric("Upstream retries", "zentinel_upstream_retries_total")
        self._print_metric("Health check failures", "zentinel_upstream_health_check_failures_total")
        print()

        # Memory analysis
        memory_results = self.results_dir / "memory-test-results.yaml"
        if memory_results.exists():
            print("MEMORY ANALYSIS")
            print("-" * 40)
            with open(memory_results) as f:
                print(f.read())

        # Final verdict
        print("=" * 60)
        if failed_scenarios == 0:
            print("RESULT: ✓ ALL SCENARIOS PASSED")
        else:
            print(f"RESULT: ✗ {failed_scenarios} SCENARIO(S) FAILED")
        print("=" * 60)

    def _print_metric(self, label: str, metric_prefix: str):
        """Print metrics matching a prefix."""
        total = 0
        for key, value in self.metrics.items():
            if key.startswith(metric_prefix):
                total += value

        if total > 0:
            print(f"  {label}: {int(total)}")


def main():
    parser = argparse.ArgumentParser(
        description="Analyze Zentinel chaos test results"
    )
    parser.add_argument(
        "results_dir",
        help="Path to results directory"
    )
    parser.add_argument(
        "--json",
        action="store_true",
        help="Output results as JSON"
    )

    args = parser.parse_args()

    if not os.path.isdir(args.results_dir):
        print(f"Error: Results directory not found: {args.results_dir}")
        sys.exit(2)

    analyzer = ChaosResultsAnalyzer(args.results_dir)
    success = analyzer.analyze()

    if args.json:
        output = {
            "success": success,
            "scenarios": [
                {
                    "name": s.name,
                    "status": s.status,
                    "tests_run": s.tests_run,
                    "tests_passed": s.tests_passed,
                    "tests_failed": s.tests_failed,
                    "errors": s.errors
                }
                for s in analyzer.scenarios
            ],
            "chaos_events_count": len(analyzer.chaos_events),
            "metrics_count": len(analyzer.metrics)
        }
        print(json.dumps(output, indent=2))

    sys.exit(0 if success else 1)


if __name__ == "__main__":
    main()
