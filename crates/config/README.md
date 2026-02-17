# Zentinel Configuration

Configuration loading, parsing, validation, and hot-reload support for Zentinel reverse proxy.

## Features

- **Multiple Formats**: KDL (primary), JSON, and TOML configuration support
- **Schema Validation**: Comprehensive validation with informative error messages
- **Hot Reload**: Watch configuration files for changes and reload without restart
- **Multi-File Support**: Split configuration across multiple files
- **Secure Defaults**: Security-first default values throughout
- **Namespace Support**: Hierarchical organization for multi-tenant deployments

## Quick Start

### Minimal Configuration (KDL)

```kdl
schema-version "1.0"

server {
    worker-threads 0  // Auto-detect CPU cores
}

listeners {
    listener "http" {
        address "0.0.0.0:8080"
        protocol "http"
    }
}

upstreams {
    upstream "backend" {
        target "127.0.0.1:3000"
    }
}

routes {
    route "api" {
        matches {
            path-prefix "/api"
        }
        upstream "backend"
    }
}
```

### Loading Configuration

```rust
use zentinel_config::Config;

// From file (format detected by extension)
let config = Config::from_file("zentinel.kdl")?;

// From KDL string
let config = Config::from_kdl(kdl_content)?;

// Default embedded configuration
let config = Config::default_embedded()?;

// Validate configuration
config.validate()?;
```

## Configuration Sections

| Section | Description |
|---------|-------------|
| `server` | Global server settings (workers, connections, shutdown) |
| `listeners` | Port bindings with TLS and protocol settings |
| `routes` | Request routing rules and policies |
| `upstreams` | Backend server pools with health checks |
| `filters` | Reusable filter definitions (rate-limit, headers, etc.) |
| `agents` | External processing agents (WAF, auth, custom) |
| `waf` | Web Application Firewall configuration |
| `observability` | Metrics, logging, and tracing |
| `limits` | Global resource limits |
| `cache` | HTTP response caching |
| `namespaces` | Hierarchical organization |

## Documentation

Detailed documentation is available in the [`docs/`](./docs/) directory:

- [KDL Configuration Format](./docs/kdl-format.md) - Syntax guide and examples
- [Schema Reference](./docs/schema.md) - Complete configuration schema
- [Validation & Defaults](./docs/validation.md) - Validation rules and default values
- [Examples](./docs/examples.md) - Common configuration patterns

## Schema Version

The configuration uses semantic versioning for compatibility:

```kdl
schema-version "1.0"
```

| Version | Status |
|---------|--------|
| `1.0` | Current (supported) |

Older versions may not load. Newer versions load with a warning.

## Service Types

Routes can serve different types of content:

| Type | Description |
|------|-------------|
| `web` | Traditional web service (default) |
| `api` | REST API with JSON responses |
| `static` | Static file hosting |
| `builtin` | Built-in handlers (health, metrics, status) |
| `inference` | LLM/AI inference with token-based rate limiting |

## Built-in Handlers

For `service-type "builtin"`:

| Handler | Description |
|---------|-------------|
| `status` | JSON status page with version/uptime |
| `health` | Health check (returns 200 if healthy) |
| `metrics` | Prometheus metrics endpoint |
| `config` | Configuration dump (admin) |
| `upstreams` | Upstream health status (admin) |
| `cache-stats` | Cache statistics (admin) |
| `cache-purge` | Cache purge endpoint (admin) |

## Filter Types

Built-in filters for request/response processing:

| Filter | Phase | Description |
|--------|-------|-------------|
| `rate-limit` | Request | Token bucket rate limiting |
| `headers` | Both | Header manipulation |
| `compress` | Response | Response compression |
| `cors` | Both | CORS handling |
| `timeout` | Request | Timeout override |
| `log` | Both | Request/response logging |
| `geo` | Request | GeoIP filtering |
| `agent` | Both | External agent processing |

## Hot Reload

Enable automatic configuration reload:

```kdl
server {
    auto-reload true
}
```

Or manually trigger reload:

```rust
config.reload("zentinel.kdl")?;
```

## Multi-File Configuration

Split configuration across multiple files:

```
config/
├── main.kdl           # Server, listeners
├── routes/
│   ├── api.kdl        # API routes
│   └── web.kdl        # Web routes
├── upstreams/
│   └── backends.kdl   # Backend pools
└── agents/
    └── waf.kdl        # WAF agent
```

Load with:

```rust
use zentinel_config::MultiFileLoader;

let loader = MultiFileLoader::new("config/");
let config = loader.load()?;
```

## Default Configuration

When no configuration file is provided, Zentinel uses an embedded default:

- HTTP listener on `0.0.0.0:8080`
- Admin listener on `0.0.0.0:9090`
- Built-in status, health, and metrics endpoints
- Sensible resource limits

## Validation

Configuration is validated for:

- Schema version compatibility
- Required fields presence
- Reference integrity (routes → upstreams, filters → agents)
- Value constraints (timeouts > 0, valid addresses, etc.)
- Security checks (TLS settings, limits)

```rust
// Validation happens automatically on load, or explicitly:
config.validate()?;
```

## Error Messages

Parse errors include context for debugging:

```
KDL configuration parse error:

  Expected closing brace

  --> at line 15, column 1
   14 | upstream "backend" {
   15 |     target "127.0.0.1:3000"
      | ^ expected '}'
   16 | }

  Help: Check for unclosed blocks or missing braces
```
