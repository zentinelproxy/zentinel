# Sentinel Test Makefile
# Provides convenient targets for running various test scenarios

.PHONY: all help up down build test test-quick test-echo test-ratelimit test-waf test-security test-performance logs clean

DOCKER_COMPOSE = docker compose -f ../docker-compose.yml
DOCKER_COMPOSE_TEST = docker compose -f ../docker-compose.yml -f ../docker-compose.test.yml

# Default target
all: test

# Help
help:
	@echo "Sentinel Test Targets"
	@echo "====================="
	@echo ""
	@echo "Environment:"
	@echo "  up           - Start the test environment"
	@echo "  down         - Stop the test environment"
	@echo "  build        - Build Docker images"
	@echo "  logs         - Show container logs"
	@echo "  clean        - Remove all test containers and volumes"
	@echo ""
	@echo "Tests:"
	@echo "  test         - Run all integration tests"
	@echo "  test-quick   - Run quick smoke tests only"
	@echo "  test-echo    - Test echo agent scenarios"
	@echo "  test-ratelimit - Test rate limit agent scenarios"
	@echo "  test-waf     - Test WAF agent security scenarios"
	@echo "  test-security - Run full security test suite"
	@echo "  test-performance - Run performance/load tests"
	@echo ""
	@echo "Local (non-Docker):"
	@echo "  test-local   - Run tests against local binaries"
	@echo ""

# Build Docker images
build:
	@echo "Building Sentinel Docker images..."
	cd .. && $(DOCKER_COMPOSE) build

# Start test environment
up:
	@echo "Starting test environment..."
	cd .. && $(DOCKER_COMPOSE) up -d
	@echo "Waiting for services to be ready..."
	@sleep 10
	@echo "Test environment ready!"
	@echo ""
	@echo "Services:"
	@echo "  Proxy:      http://localhost:8080"
	@echo "  Metrics:    http://localhost:9090"
	@echo "  Prometheus: http://localhost:9091"
	@echo "  Grafana:    http://localhost:3000 (admin/sentinel)"
	@echo "  Jaeger:     http://localhost:16686"

# Start test environment with additional test services
up-test:
	@echo "Starting full test environment..."
	cd .. && $(DOCKER_COMPOSE_TEST) up -d
	@sleep 10
	@echo "Full test environment ready!"

# Stop test environment
down:
	@echo "Stopping test environment..."
	cd .. && $(DOCKER_COMPOSE) down

# Show logs
logs:
	cd .. && $(DOCKER_COMPOSE) logs -f

logs-proxy:
	cd .. && $(DOCKER_COMPOSE) logs -f proxy

logs-agents:
	cd .. && $(DOCKER_COMPOSE) logs -f ratelimit waf echo

# Clean up everything
clean:
	@echo "Cleaning up test environment..."
	cd .. && $(DOCKER_COMPOSE) down --volumes --remove-orphans
	docker system prune -f

# Run all integration tests
test: up
	@echo ""
	@echo "Running integration tests..."
	./integration_test.sh --no-build --keep
	@$(MAKE) down

# Run quick smoke tests
test-quick: up
	@echo ""
	@echo "Running quick smoke tests..."
	./integration_test.sh --no-build --quick --keep
	@$(MAKE) down

# Run echo agent tests
test-echo: up
	@echo ""
	@echo "Running echo agent tests..."
	./scenarios/test_echo_agent.sh
	@$(MAKE) down

# Run rate limit agent tests
test-ratelimit: up
	@echo ""
	@echo "Running rate limit agent tests..."
	./scenarios/test_ratelimit_agent.sh
	@$(MAKE) down

# Run WAF agent tests
test-waf: up
	@echo ""
	@echo "Running WAF agent security tests..."
	./scenarios/test_waf_agent.sh
	@$(MAKE) down

# Run security-focused tests
test-security: up
	@echo ""
	@echo "Running security test suite..."
	./scenarios/test_waf_agent.sh
	./test_waf.sh || true
	@$(MAKE) down

# Run performance tests
test-performance: up
	@echo ""
	@echo "Running performance tests..."
	@echo "Warming up..."
	@for i in $$(seq 1 100); do curl -sf http://localhost:8080/get >/dev/null 2>&1 || true; done
	@echo ""
	@echo "Running load test..."
	@START=$$(date +%s%N); \
	for i in $$(seq 1 1000); do \
		curl -sf http://localhost:8080/get >/dev/null 2>&1 & \
	done; \
	wait; \
	END=$$(date +%s%N); \
	DURATION=$$(( (END - START) / 1000000 )); \
	RPS=$$(( 1000 * 1000 / DURATION )); \
	echo "1000 requests completed in $${DURATION}ms (~$${RPS} req/s)"
	@$(MAKE) down

# Run tests against local binaries (not Docker)
test-local:
	@echo "Running tests against local binaries..."
	./test_agents.sh

# Watch test logs
watch:
	@echo "Watching test environment..."
	@watch -n 2 'docker compose -f ../docker-compose.yml ps; echo ""; curl -s http://localhost:9090/health 2>/dev/null || echo "Proxy not responding"'

# Interactive shell in test container
shell:
	cd .. && $(DOCKER_COMPOSE) exec proxy /bin/bash

# Check service health
health:
	@echo "Checking service health..."
	@echo ""
	@echo -n "Proxy:     "; curl -sf http://localhost:9090/health && echo "OK" || echo "DOWN"
	@echo -n "Backend:   "; curl -sf http://localhost:8081/status/200 >/dev/null && echo "OK" || echo "DOWN"
	@echo -n "RateLimit: "; curl -sf http://localhost:9092/metrics >/dev/null && echo "OK" || echo "DOWN"
	@echo -n "WAF:       "; curl -sf http://localhost:9094/metrics >/dev/null && echo "OK" || echo "DOWN"
	@echo -n "Prometheus:"; curl -sf http://localhost:9091/-/ready >/dev/null && echo "OK" || echo "DOWN"
	@echo -n "Grafana:   "; curl -sf http://localhost:3000/api/health >/dev/null && echo "OK" || echo "DOWN"
	@echo -n "Jaeger:    "; curl -sf http://localhost:16686/ >/dev/null && echo "OK" || echo "DOWN"
