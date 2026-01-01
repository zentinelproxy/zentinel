# Sentinel Chaos Tests Makefile
#
# Quick reference:
#   make test          - Run all chaos tests
#   make quick         - Run quick subset of tests
#   make test-<name>   - Run specific scenario
#   make up            - Start test environment
#   make down          - Stop test environment
#   make logs          - View container logs
#   make clean         - Remove test results
#

.PHONY: help test quick all up down logs clean build

# Default target
help:
	@echo "Sentinel Chaos Tests"
	@echo ""
	@echo "Usage:"
	@echo "  make test              Run all chaos tests"
	@echo "  make quick             Run quick subset (recommended for validation)"
	@echo ""
	@echo "Individual scenarios:"
	@echo "  make test-agent-crash       Test agent crash handling"
	@echo "  make test-agent-timeout     Test agent timeout handling"
	@echo "  make test-circuit-breaker   Test circuit breaker state transitions"
	@echo "  make test-backend-crash     Test backend crash and failover"
	@echo "  make test-backend-5xx       Test 5xx error handling"
	@echo "  make test-all-backends-down Test all backends unavailable"
	@echo "  make test-fail-open         Test fail-open mode"
	@echo "  make test-fail-closed       Test fail-closed mode"
	@echo "  make test-health-recovery   Test health check recovery"
	@echo "  make test-memory-stability  Test memory stability under chaos"
	@echo ""
	@echo "Environment management:"
	@echo "  make up                Start test environment"
	@echo "  make down              Stop test environment"
	@echo "  make logs              View container logs"
	@echo "  make ps                Show running containers"
	@echo ""
	@echo "Other:"
	@echo "  make build             Build Docker images"
	@echo "  make clean             Remove test results"
	@echo "  make help              Show this help message"

# ============================================================================
# Main test targets
# ============================================================================

test: all
all:
	./run-chaos-test.sh --all

quick:
	./run-chaos-test.sh --quick

# ============================================================================
# Individual scenario targets
# ============================================================================

test-agent-crash:
	./run-chaos-test.sh --scenario agent-crash --skip-cleanup

test-agent-timeout:
	./run-chaos-test.sh --scenario agent-timeout --skip-cleanup

test-circuit-breaker:
	./run-chaos-test.sh --scenario circuit-breaker --skip-cleanup

test-backend-crash:
	./run-chaos-test.sh --scenario backend-crash --skip-cleanup

test-backend-5xx:
	./run-chaos-test.sh --scenario backend-5xx --skip-cleanup

test-all-backends-down:
	./run-chaos-test.sh --scenario all-backends-down --skip-cleanup

test-fail-open:
	./run-chaos-test.sh --scenario fail-open --skip-cleanup

test-fail-closed:
	./run-chaos-test.sh --scenario fail-closed --skip-cleanup

test-health-recovery:
	./run-chaos-test.sh --scenario health-recovery --skip-cleanup

test-memory-stability:
	./run-chaos-test.sh --scenario memory-stability --skip-cleanup

# Category targets
test-agent: test-agent-crash test-agent-timeout test-circuit-breaker

test-upstream: test-backend-crash test-backend-5xx test-all-backends-down

test-resilience: test-fail-open test-fail-closed test-health-recovery test-memory-stability

# ============================================================================
# Environment management
# ============================================================================

COMPOSE = docker compose -p chaos -f docker-compose.chaos.yml

build:
	$(COMPOSE) build

up:
	$(COMPOSE) up -d
	@echo "Waiting for services to be ready..."
	@sleep 5
	@echo "Environment ready. Proxy: http://localhost:8080, Metrics: http://localhost:9090/metrics"

down:
	$(COMPOSE) down --volumes --remove-orphans

logs:
	$(COMPOSE) logs -f

logs-proxy:
	$(COMPOSE) logs -f proxy

logs-echo:
	$(COMPOSE) logs -f echo

ps:
	$(COMPOSE) ps

# ============================================================================
# Cleanup
# ============================================================================

clean:
	rm -rf results/
	@echo "Removed test results"

clean-all: clean down
	@echo "Cleaned up all test artifacts"

# ============================================================================
# Development helpers
# ============================================================================

shell-proxy:
	$(COMPOSE) exec proxy /bin/sh

shell-echo:
	$(COMPOSE) exec echo /bin/sh

# Quick health check
health:
	@curl -sf http://localhost:9090/health && echo "Proxy: healthy" || echo "Proxy: not responding"

# Fetch metrics
metrics:
	@curl -sf http://localhost:9090/metrics | grep -E "^sentinel_" | head -20
