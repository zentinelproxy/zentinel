# Inference Module

Token-based rate limiting and management for LLM/AI routing.

## Overview

The inference module provides specialized handling for LLM inference endpoints:

- **Token-based rate limiting** - Limits based on token consumption, not just requests
- **Token budgets** - Daily/monthly cumulative usage limits
- **Cost tracking** - Dollar cost attribution per model
- **Guardrails** - Prompt injection and PII detection
- **Model routing** - Route to different providers based on model
- **Fallback** - Automatic failover between providers
- **Streaming support** - Token counting for SSE responses

## Architecture

```
┌─────────────────────────────────────────────────────────────────────┐
│                     Inference Pipeline                               │
└─────────────────────────────────────────────────────────────────────┘

     Request
        │
        ▼
┌───────────────────┐
│   Extract Model   │  Parse model from request body
│   & Estimate      │  Count input tokens (tiktoken)
└─────────┬─────────┘
          │
          ▼
┌───────────────────┐
│   Token Rate      │  Check tokens-per-minute limit
│   Limit Check     │  (separate from request rate limit)
└─────────┬─────────┘
          │
     ┌────┴────┐
     │ Limited?│───Yes──▶ Return 429 + retry-after
     └────┬────┘
          │ No
          ▼
┌───────────────────┐
│   Budget Check    │  Check daily/monthly token budget
│                   │
└─────────┬─────────┘
          │
     ┌────┴────┐
     │Exhausted│───Yes──▶ Return 429 + budget error
     └────┬────┘
          │ No
          ▼
┌───────────────────┐
│   Guardrails      │  Prompt injection detection
│   (optional)      │  PII detection
└─────────┬─────────┘
          │
     ┌────┴────┐
     │ Blocked?│───Yes──▶ Return 400 + violation details
     └────┬────┘
          │ No
          ▼
┌───────────────────┐
│   Model Routing   │  Select upstream by model pattern
│                   │  gpt-4* → OpenAI, claude-* → Anthropic
└─────────┬─────────┘
          │
          ▼
┌───────────────────┐
│   Upstream Pool   │  Least-tokens-queued balancing
│   Selection       │  Inference-aware health checks
└─────────┬─────────┘
          │
          ▼
┌───────────────────┐
│   Forward         │  Stream response, count output tokens
│   Request         │
└─────────┬─────────┘
          │
          ▼
┌───────────────────┐
│   Cost Tracking   │  Calculate $ cost from token usage
│   & Metrics       │  Update budget, emit metrics
└───────────────────┘
```

## Token Rate Limiting

Unlike request-based rate limiting, token rate limiting accounts for the actual computational cost of LLM requests.

### Configuration

```kdl
route "/v1/chat/completions" {
    service-type "inference"
    inference {
        provider "openai"

        rate-limit {
            // Token-based limits
            tokens-per-minute 100000
            burst-tokens 10000

            // Can also combine with request limits
            requests-per-minute 100
        }
    }
}
```

### How It Works

1. **Request arrives** - Parse the `model` and `messages` from the request body
2. **Count input tokens** - Use tiktoken (or estimation) to count tokens
3. **Check rate limit** - Verify tokens-per-minute not exceeded
4. **Track response tokens** - For streaming responses, count tokens in SSE events
5. **Update usage** - Add input + output tokens to usage counter

### Token Counting

The module supports multiple token counting strategies:

```rust
pub enum TokenCounter {
    // Exact counting using tiktoken (requires feature)
    Tiktoken(TiktokenEncoder),

    // Estimation based on character/word count
    Estimation(EstimationConfig),

    // Provider-specific counters
    OpenAI(OpenAICounter),
    Anthropic(AnthropicCounter),
}
```

**Tiktoken Feature:**

```toml
[features]
tiktoken = ["tiktoken-rs"]
```

## Token Budgets

Cumulative token usage limits over time periods.

### Configuration

```kdl
route "/v1/chat/completions" {
    inference {
        budget {
            // Daily budget (resets at midnight UTC)
            daily-limit 1000000

            // Monthly budget (resets on 1st)
            monthly-limit 10000000

            // Enforce budget (reject requests when exhausted)
            enforce true

            // Alert when reaching threshold
            alert-threshold 0.8
        }
    }
}
```

### Budget Tracking

```rust
pub struct TokenBudgetTracker {
    daily_usage: AtomicU64,
    monthly_usage: AtomicU64,
    daily_limit: Option<u64>,
    monthly_limit: Option<u64>,
    last_daily_reset: AtomicU64,
    last_monthly_reset: AtomicU64,
}

impl TokenBudgetTracker {
    pub fn check(&self, tokens: u64) -> BudgetResult;
    pub fn record_usage(&self, tokens: u64);
    pub fn remaining_daily(&self) -> Option<u64>;
    pub fn remaining_monthly(&self) -> Option<u64>;
}
```

### Budget Response

When budget is exhausted:

```json
{
  "error": {
    "type": "budget_exceeded",
    "message": "Daily token budget exhausted",
    "budget_type": "daily",
    "limit": 1000000,
    "used": 1000000,
    "resets_at": "2024-01-16T00:00:00Z"
  }
}
```

## Cost Tracking

Calculate dollar costs based on token usage and model pricing.

### Configuration

```kdl
route "/v1/chat/completions" {
    inference {
        cost-attribution {
            enabled true

            pricing {
                model "gpt-4*" {
                    input-cost-per-million 30.0
                    output-cost-per-million 60.0
                }
                model "gpt-3.5-turbo*" {
                    input-cost-per-million 0.5
                    output-cost-per-million 1.5
                }
                model "claude-3-opus*" {
                    input-cost-per-million 15.0
                    output-cost-per-million 75.0
                }
                model "claude-3-sonnet*" {
                    input-cost-per-million 3.0
                    output-cost-per-million 15.0
                }
            }

            // Add cost header to response
            include-header true
            header-name "X-Inference-Cost"
        }
    }
}
```

### Cost Calculator

```rust
pub struct CostCalculator {
    pricing: HashMap<GlobPattern, ModelPricing>,
}

pub struct ModelPricing {
    input_cost_per_million: f64,
    output_cost_per_million: f64,
}

impl CostCalculator {
    pub fn calculate(&self, model: &str, input_tokens: u64, output_tokens: u64) -> f64;
}
```

### Metrics

Cost metrics are exported for monitoring:

```
# Total cost in dollars
zentinel_inference_cost_dollars_total{route="chat", model="gpt-4"} 1.23

# Cost per request
zentinel_inference_cost_per_request{route="chat", model="gpt-4", quantile="0.5"} 0.05
```

## Guardrails

Semantic inspection for prompt injection and PII detection.

### Configuration

```kdl
route "/v1/chat/completions" {
    inference {
        guardrails {
            prompt-injection {
                enabled true
                agent "guardrail-agent"
                action "block"
                // Or "warn" to log but allow
            }

            pii-detection {
                enabled true
                agent "pii-agent"
                action "redact"
                // Types: ssn, credit-card, email, phone, etc.
                types ["ssn", "credit-card"]
            }
        }
    }
}
```

### Guardrail Response

When blocked:

```json
{
  "error": {
    "type": "guardrail_violation",
    "message": "Request blocked by guardrail",
    "guardrail": "prompt_injection",
    "confidence": 0.95,
    "details": "Detected injection pattern in user message"
  }
}
```

## Model Routing

Route requests to different upstreams based on the model.

### Configuration

```kdl
route "/v1/chat/completions" {
    inference {
        model-routing {
            // Pattern-based routing
            model "gpt-4*" upstream="openai"
            model "gpt-3.5*" upstream="openai"
            model "claude-*" upstream="anthropic" provider="anthropic"
            model "llama-*" upstream="local-llama"

            // Default if no pattern matches
            default-upstream "openai"
        }
    }
}
```

### Model Mapping for Fallback

Map models between providers when falling back:

```kdl
route "/v1/chat/completions" {
    inference {
        fallback {
            upstreams {
                upstream "anthropic" provider="anthropic" {
                    model-mapping {
                        "gpt-4" "claude-3-opus"
                        "gpt-4-turbo" "claude-3-opus"
                        "gpt-3.5-turbo" "claude-3-sonnet"
                    }
                }
            }

            triggers {
                on-health-failure true
                on-budget-exhausted true
                on-error-codes [429, 503]
            }
        }
    }
}
```

## Streaming Support

Token counting for Server-Sent Event (SSE) streaming responses.

### How It Works

1. **Detect streaming** - Check for `stream: true` in request
2. **Proxy SSE** - Forward events from upstream to client
3. **Parse events** - Extract token chunks from SSE data
4. **Count tokens** - Accumulate output tokens from chunks
5. **Final count** - Get final token count from `usage` field or sum

### SSE Event Parsing

```rust
pub struct StreamingTokenCounter {
    accumulated_tokens: AtomicU64,
}

impl StreamingTokenCounter {
    pub fn process_event(&self, event: &SseEvent) {
        if let Some(choice) = event.data.get("choices").and_then(|c| c.get(0)) {
            if let Some(delta) = choice.get("delta").and_then(|d| d.get("content")) {
                let tokens = estimate_tokens(delta.as_str().unwrap_or(""));
                self.accumulated_tokens.fetch_add(tokens, Ordering::Relaxed);
            }
        }
    }

    pub fn finalize(&self, usage: Option<&Usage>) -> u64 {
        usage.map(|u| u.completion_tokens)
            .unwrap_or_else(|| self.accumulated_tokens.load(Ordering::Relaxed))
    }
}
```

## Load Balancing for Inference

Special load balancing algorithm for LLM endpoints.

### Least Tokens Queued

```rust
pub struct LeastTokensQueuedBalancer {
    targets: Vec<InferenceTarget>,
}

pub struct InferenceTarget {
    address: SocketAddr,
    queued_tokens: AtomicU64,
    processing_tokens: AtomicU64,
    max_tokens: u64,
}

impl LeastTokensQueuedBalancer {
    pub fn select(&self, estimated_tokens: u64) -> Option<&InferenceTarget> {
        // Find target with lowest (queued + processing) tokens
        // that has capacity for the estimated tokens
        self.targets
            .iter()
            .filter(|t| t.has_capacity(estimated_tokens))
            .min_by_key(|t| t.total_tokens())
    }
}
```

### Inference Health Checks

Specialized health checks for inference endpoints:

```kdl
upstream "openai" {
    health-check {
        type "inference"

        // Query /v1/models endpoint
        models-endpoint "/v1/models"

        // Or send a minimal completion probe
        probe {
            model "gpt-3.5-turbo"
            messages [{"role": "user", "content": "hi"}]
            max-tokens 1
        }

        interval-secs 30
        timeout-secs 10
    }
}
```

## Metrics

Inference-specific metrics:

```
# Token rate limiting
zentinel_inference_rate_limit_tokens_allowed_total{route="chat"}
zentinel_inference_rate_limit_tokens_limited_total{route="chat"}
zentinel_inference_rate_limit_current_tokens{route="chat"}

# Token budgets
zentinel_inference_budget_tokens_used{route="chat", period="daily"}
zentinel_inference_budget_tokens_remaining{route="chat", period="daily"}
zentinel_inference_budget_exhausted_total{route="chat", period="daily"}

# Token usage
zentinel_inference_input_tokens_total{route="chat", model="gpt-4"}
zentinel_inference_output_tokens_total{route="chat", model="gpt-4"}
zentinel_inference_tokens_per_request{route="chat", model="gpt-4", quantile="0.5"}

# Cost
zentinel_inference_cost_dollars_total{route="chat", model="gpt-4"}

# Guardrails
zentinel_inference_guardrail_blocked_total{route="chat", guardrail="prompt_injection"}
zentinel_inference_guardrail_latency_ms{route="chat", guardrail="prompt_injection"}

# Model routing
zentinel_inference_model_requests_total{route="chat", model="gpt-4", upstream="openai"}
zentinel_inference_fallback_total{route="chat", from="openai", to="anthropic"}
```

## Example Configuration

Complete inference route configuration:

```kdl
upstreams {
    upstream "openai" {
        target "api.openai.com:443"
        tls {
            sni "api.openai.com"
        }
        health-check {
            type "inference"
            models-endpoint "/v1/models"
            interval-secs 30
        }
    }

    upstream "anthropic" {
        target "api.anthropic.com:443"
        tls {
            sni "api.anthropic.com"
        }
    }
}

agents {
    agent "guardrail-agent" {
        type "custom"
        transport {
            unix-socket "/var/run/guardrail.sock"
        }
        events ["request-body"]
        timeout-ms 100
    }
}

routes {
    route "chat" {
        matches {
            path-prefix "/v1/chat/completions"
        }

        service-type "inference"
        upstream "openai"

        inference {
            provider "openai"

            rate-limit {
                tokens-per-minute 100000
                burst-tokens 10000
                requests-per-minute 100
            }

            budget {
                daily-limit 1000000
                monthly-limit 10000000
                enforce true
                alert-threshold 0.8
            }

            cost-attribution {
                enabled true
                pricing {
                    model "gpt-4*" {
                        input-cost-per-million 30.0
                        output-cost-per-million 60.0
                    }
                    model "gpt-3.5-turbo*" {
                        input-cost-per-million 0.5
                        output-cost-per-million 1.5
                    }
                }
            }

            guardrails {
                prompt-injection {
                    enabled true
                    agent "guardrail-agent"
                    action "block"
                }
            }

            model-routing {
                model "gpt-4*" upstream="openai"
                model "claude-*" upstream="anthropic" provider="anthropic"
                default-upstream "openai"
            }

            fallback {
                upstreams {
                    upstream "anthropic" provider="anthropic" {
                        model-mapping {
                            "gpt-4" "claude-3-opus"
                            "gpt-3.5-turbo" "claude-3-sonnet"
                        }
                    }
                }
                triggers {
                    on-health-failure true
                    on-budget-exhausted true
                    on-error-codes [429, 503]
                }
            }
        }
    }
}
```
