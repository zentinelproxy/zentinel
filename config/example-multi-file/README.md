# Multi-File Configuration for Sentinel

Sentinel supports loading configuration from multiple KDL files, allowing you to organize your configuration in a maintainable, modular way. This is especially important for production deployments where configuration can become complex.

## Features

- **Modular Organization**: Split configuration across multiple files by concern
- **Environment-Specific Overrides**: Different settings for dev, staging, production
- **Include Patterns**: Flexible file inclusion with glob patterns
- **Duplicate Detection**: Automatic detection of conflicting definitions
- **Hot Reload Support**: Changes to any file trigger configuration reload
- **Convention-Based Structure**: Optional standardized directory layout

## Directory Structure

### Recommended Convention

```
config/
├── sentinel.kdl              # Main configuration file
├── listeners/                # Listener definitions
│   ├── http.kdl
│   └── https.kdl
├── routes/                   # Route definitions
│   ├── api.kdl
│   ├── static.kdl
│   └── websocket.kdl
├── upstreams/                # Backend server pools
│   ├── backends.kdl
│   ├── cache.kdl
│   └── database.kdl
├── agents/                   # Agent configurations
│   ├── waf.kdl
│   ├── auth.kdl
│   ├── rate-limiter.kdl
│   └── lua-scripts.kdl
├── policies/                 # Security and routing policies
│   ├── cors.kdl
│   ├── security-headers.kdl
│   └── rate-limits.kdl
├── environments/             # Environment-specific overrides
│   ├── development.kdl
│   ├── staging.kdl
│   └── production.kdl
└── custom/                   # Custom extensions
    └── *.kdl
```

## Usage

### Basic Multi-File Loading

Load all `.kdl` files from a directory:

```bash
sentinel --config-dir /etc/sentinel
```

### With Environment Override

Load base configuration plus environment-specific settings:

```bash
sentinel --config-dir /etc/sentinel --environment production
```

### Explicit File List

Load specific files in order:

```bash
sentinel --config-files \
  /etc/sentinel/base.kdl \
  /etc/sentinel/routes/*.kdl \
  /etc/sentinel/prod-override.kdl
```

## File Organization Examples

### Main Configuration (sentinel.kdl)

The main file contains global settings and defaults:

```kdl
// sentinel.kdl - Core server configuration
server {
    worker-threads 4
    graceful-shutdown-timeout "30s"
}

limits {
    max-connections 10000
    request-timeout "30s"
}

logging {
    level "info"
    format "json"
}

// Files from subdirectories are loaded automatically
```

### Listeners (listeners/https.kdl)

Each listener in its own file for clarity:

```kdl
// listeners/https.kdl
listener "https" {
    address "0.0.0.0:443"
    protocol "https"
    
    tls {
        cert "/etc/sentinel/certs/server.crt"
        key "/etc/sentinel/certs/server.key"
        min-version "TLS1.2"
    }
    
    http2 {
        enabled true
        max-concurrent-streams 100
    }
}
```

### Routes (routes/api.kdl)

Group related routes together:

```kdl
// routes/api.kdl
route "api-v1" {
    path {
        prefix "/api/v1"
    }
    
    upstream "api-backend"
    
    agents ["auth", "rate-limiter", "waf"]
}

route "api-v2" {
    path {
        prefix "/api/v2"
    }
    
    upstream "api-backend-v2"
}
```

### Upstreams (upstreams/backends.kdl)

Backend configurations organized by service:

```kdl
// upstreams/backends.kdl
upstream "api-backend" {
    targets [
        {
            address "10.0.1.10"
            port 8080
            weight 100
        }
        {
            address "10.0.1.11"
            port 8080
            weight 100
        }
    ]
    
    load-balancing {
        algorithm "round-robin"
    }
    
    health-check {
        enabled true
        path "/health"
        interval "5s"
    }
}
```

### Environment Overrides (environments/production.kdl)

Production-specific settings that override defaults:

```kdl
// environments/production.kdl
// These settings override base configuration when --environment=production

server {
    worker-threads 16  // More workers for production
}

limits {
    max-connections 100000  // Higher limits for production
}

logging {
    level "warn"  // Less verbose in production
}

// Override specific upstream for production
upstream "api-backend" {
    targets [
        {
            address "prod-api-1.internal"
            port 8080
        }
        {
            address "prod-api-2.internal"
            port 8080
        }
        // ... more production servers
    ]
}
```

## Include Directives

You can explicitly include files within any KDL file:

```kdl
// Include specific files
include "custom/extra-routes.kdl"

// Include with glob patterns
include "policies/*.kdl"

// Include from absolute path
include "/opt/sentinel/shared-config.kdl"
```

## Merging Rules

When loading multiple files, Sentinel follows these merging rules:

### Collections (Arrays)
- **Listeners**: Merged by ID, duplicates cause error
- **Routes**: Merged by ID, duplicates cause error  
- **Agents**: Merged by ID, duplicates cause error

### Maps (Key-Value)
- **Upstreams**: Merged by name, last definition wins
- **Metadata**: Merged, last value wins for duplicate keys

### Singleton Configs
- **Server**: Last definition wins
- **TLS**: Last definition wins
- **Limits**: Last definition wins
- **Logging**: Last definition wins
- **Metrics**: Last definition wins

## Best Practices

### 1. Use Consistent Naming

Follow a naming convention for IDs:
```kdl
route "api-v1-users" { ... }      // Good: descriptive and versioned
route "route1" { ... }             // Bad: non-descriptive
```

### 2. Group Related Configuration

Keep related configurations together:
```
routes/
├── api/
│   ├── v1.kdl
│   ├── v2.kdl
│   └── graphql.kdl
├── static.kdl
└── websocket.kdl
```

### 3. Use Environment Variables

For sensitive data and environment-specific values:
```kdl
upstream "database" {
    targets [
        {
            address "$DB_HOST"
            port "$DB_PORT"
        }
    ]
    
    auth {
        username "$DB_USER"
        password "$DB_PASSWORD"
    }
}
```

### 4. Document Your Configuration

Add comments explaining complex configurations:
```kdl
// This route handles legacy API compatibility
// It will be deprecated in Q3 2024
route "api-legacy" {
    // Special handling for old clients
    // ...
}
```

### 5. Version Control Friendly

Keep each logical unit in separate files for better Git diffs:
- One route definition per file for complex routes
- One upstream per file for critical services
- Separate files for each environment

### 6. Validation

Always validate configuration before deploying:
```bash
# Dry-run to validate without starting
sentinel --config-dir /etc/sentinel --dry-run

# Test specific environment
sentinel --config-dir /etc/sentinel --environment staging --validate
```

## Advanced Features

### Conditional Includes

Include files based on conditions:
```kdl
// Only include if environment variable is set
include env("CUSTOM_CONFIG") if env("ENABLE_CUSTOM") == "true"

// Include based on hostname
include "hosts/${HOSTNAME}.kdl" if exists
```

### Template Substitution

Use templates for repeated patterns:
```kdl
template upstream-base {
    health-check {
        enabled true
        interval "5s"
        timeout "3s"
    }
    
    connection-pool {
        max-connections 1000
    }
}

upstream "api" extends="upstream-base" {
    targets [...]
}
```

### Config Fragments

Load configuration fragments from external sources:
```kdl
// Load from URL
include "https://config.internal/sentinel/shared.kdl"

// Load from S3
include "s3://config-bucket/sentinel/routes.kdl"

// Load from Kubernetes ConfigMap
include "k8s://configmap/sentinel-config/data/routes.kdl"
```

## Migration Guide

### From Single File to Multi-File

1. **Start with your existing configuration**:
```bash
cp /etc/sentinel/config.kdl /etc/sentinel/sentinel.kdl
```

2. **Extract listeners**:
```bash
mkdir /etc/sentinel/listeners
# Move listener blocks to separate files
```

3. **Extract routes**:
```bash
mkdir /etc/sentinel/routes
# Move route blocks to separate files
```

4. **Extract upstreams**:
```bash
mkdir /etc/sentinel/upstreams
# Move upstream blocks to separate files
```

5. **Test the new structure**:
```bash
sentinel --config-dir /etc/sentinel --dry-run
```

## Troubleshooting

### Common Issues

#### Duplicate ID Errors
```
Error: Duplicate route ID 'api-v1' found in:
  - /etc/sentinel/routes/api.kdl:10
  - /etc/sentinel/routes/legacy.kdl:5
```

**Solution**: Ensure all IDs are unique across files.

#### Missing Upstream References
```
Error: Route 'api' references non-existent upstream 'backend'
```

**Solution**: Ensure upstreams are defined before routes that reference them, or use proper include ordering.

#### Circular Includes
```
Error: Circular include detected:
  a.kdl -> b.kdl -> c.kdl -> a.kdl
```

**Solution**: Restructure files to eliminate circular dependencies.

### Debug Loading

Enable debug logging to see file loading order:
```bash
RUST_LOG=sentinel::config=debug sentinel --config-dir /etc/sentinel
```

### Loading Order

Files are loaded in this order:
1. `sentinel.kdl` (if exists)
2. Subdirectories (alphabetically): `agents/`, `listeners/`, `routes/`, `upstreams/`
3. Environment-specific overrides
4. Explicit includes

## Benefits of Multi-File Configuration

1. **Better Organization**: Logical separation of concerns
2. **Team Collaboration**: Different teams can own different files
3. **Easier Maintenance**: Find and update specific configurations quickly
4. **Version Control**: Cleaner diffs and merge conflict resolution
5. **Environment Management**: Clear separation between environments
6. **Modular Deployment**: Deploy configuration changes incrementally
7. **Reusability**: Share common configurations across deployments
8. **Security**: Separate sensitive configurations with different permissions

## Examples in This Directory

This directory contains a complete example of multi-file configuration:

- `sentinel.kdl` - Main configuration with global settings
- `listeners/` - HTTP and HTTPS listener configurations
- `routes/` - API and static route definitions
- `upstreams/` - Backend server pool configurations
- `environments/` - Environment-specific overrides

To test this configuration:
```bash
cd /path/to/config/example-multi-file
sentinel --config-dir . --dry-run
```

## API Reference

### CLI Options

- `--config-dir PATH` - Load all .kdl files from directory
- `--config-files FILE1,FILE2` - Load specific files
- `--environment ENV` - Apply environment-specific overrides
- `--include-pattern GLOB` - Include files matching pattern
- `--exclude-pattern GLOB` - Exclude files matching pattern
- `--strict` - Fail on configuration warnings
- `--dry-run` - Validate without starting
- `--validate` - Validate and exit

### Configuration API

```rust
use sentinel_config::{Config, MultiFileLoader};

// Load from directory
let config = Config::from_directory("/etc/sentinel")?;

// Load with environment
let config = Config::from_directory_with_env("/etc/sentinel", "production")?;

// Custom loader
let mut loader = MultiFileLoader::new("/etc/sentinel")
    .with_include("*.kdl")
    .with_exclude("*.example.kdl")
    .recursive(true)
    .strict(true);

let config = loader.load()?;
```
