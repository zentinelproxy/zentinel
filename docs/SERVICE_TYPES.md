# Service Types in Sentinel

Sentinel supports different service types to optimize handling for various kinds of traffic. Each service type provides specialized features and optimizations for its use case.

## Overview

Sentinel recognizes three primary service types:

1. **`web`** - Traditional web applications serving HTML content
2. **`api`** - REST/GraphQL APIs serving JSON/XML responses  
3. **`static`** - Static file hosting and serving

## Service Type Features

### Web Service Type (Default)

The `web` service type is optimized for traditional web applications:

- **HTML error pages** by default
- **Session affinity** support
- **Cookie handling** optimization
- **HTML/CSS/JS response compression**
- **Browser-friendly caching headers**

```kdl
route "web-app" {
    service_type "web"  // This is the default
    
    error_pages {
        default_format "html"
        pages {
            404 {
                format "html"
                template "404.html"
                message "Page not found"
            }
        }
    }
}
```

### API Service Type

The `api` service type is designed for REST APIs and microservices:

- **JSON error responses** by default
- **Schema validation** support (OpenAPI/JSON Schema)
- **Structured error responses** with error codes
- **API-specific rate limiting**
- **CORS handling** optimization
- **JSON/XML response validation**

```kdl
route "api-v1" {
    service_type "api"
    
    // Schema validation
    api_schema {
        schema_file "/etc/sentinel/schemas/openapi.yaml"
        validate_requests true
        validate_responses false  // Enable in dev/staging
        strict_mode false
        
        // Override schema for specific endpoints
        request_schema {
            type "object"
            properties {
                api_key {
                    type "string"
                    pattern "^[A-Za-z0-9]{32}$"
                }
            }
            required ["api_key"]
        }
    }
    
    // JSON error responses
    error_pages {
        default_format "json"
        pages {
            400 {
                format "json"
                message "Invalid request"
                headers {
                    "X-Error-Code" "INVALID_INPUT"
                }
            }
        }
    }
}
```

### Static Service Type

The `static` service type provides high-performance file serving:

- **Direct file serving** without upstream
- **Directory listing** (optional)
- **Automatic MIME type detection**
- **Range request support** for large files
- **Efficient caching** with ETags
- **Compression** for text files
- **SPA fallback** support

```kdl
route "static-assets" {
    service_type "static"
    upstream null  // No upstream needed
    
    static_files {
        root "/var/www/static"
        index "index.html"
        directory_listing false
        cache_control "public, max-age=86400"
        compress true
        
        // Custom MIME types
        mime_types {
            "wasm" "application/wasm"
            "mjs" "application/javascript"
        }
        
        // For SPAs: fallback to index.html
        fallback "index.html"
    }
}
```

## Error Page Configuration

Error pages can be customized per route and service type:

### Error Page Formats

- **`html`** - HTML error pages (default for `web`)
- **`json`** - JSON error responses (default for `api`)
- **`text`** - Plain text errors
- **`xml`** - XML error responses

### Configuration Structure

```kdl
error_pages {
    default_format "html|json|text|xml"
    template_dir "/path/to/templates"
    include_stack_trace false  // Never enable in production
    
    pages {
        404 {
            format "html"
            template "404.html"  // Optional custom template
            message "Custom error message"
            headers {
                "X-Custom-Header" "value"
            }
        }
        500 {
            format "json"
            message "Internal server error"
        }
    }
}
```

### Template Variables

Custom error templates can use these variables:
- `{{status}}` - HTTP status code
- `{{title}}` - Error title
- `{{message}}` - Error message
- `{{request_id}}` - Request tracking ID
- `{{timestamp}}` - Error timestamp

## API Schema Validation

For `api` service type routes, Sentinel can validate requests and responses against JSON Schema or OpenAPI specifications.

### OpenAPI Integration

```kdl
api_schema {
    schema_file "/etc/sentinel/schemas/api-v1-openapi.yaml"
    validate_requests true
    validate_responses false
    strict_mode false  // Fail on additional properties
}
```

### Inline JSON Schema

```kdl
api_schema {
    request_schema {
        type "object"
        properties {
            username {
                type "string"
                minLength 3
                maxLength 20
            }
            email {
                type "string"
                format "email"
            }
            age {
                type "integer"
                minimum 18
            }
        }
        required ["username", "email"]
    }
}
```

### Validation Errors

When validation fails, Sentinel returns a structured error response:

```json
{
    "error": "Validation failed",
    "status": 400,
    "validation_errors": [
        {
            "field": "email",
            "message": "Invalid email format",
            "value": "not-an-email"
        },
        {
            "field": "age",
            "message": "Must be at least 18",
            "value": 16
        }
    ],
    "request_id": "abc-123-def"
}
```

## Static File Serving

The `static` service type provides efficient file serving capabilities:

### Basic Configuration

```kdl
static_files {
    root "/var/www/static"
    index "index.html"
    directory_listing false
    cache_control "public, max-age=3600"
    compress true
}
```

### Configuration Options

| Option | Description | Default |
|--------|-------------|---------|
| `root` | Root directory for files | Required |
| `index` | Default index file | `index.html` |
| `directory_listing` | Enable directory browsing | `false` |
| `cache_control` | Cache-Control header value | `public, max-age=3600` |
| `compress` | Enable compression | `true` |
| `mime_types` | Custom MIME type mappings | `{}` |
| `fallback` | Fallback file for SPA routing | `null` |

### Single Page Application (SPA) Support

For SPAs with client-side routing:

```kdl
route "spa" {
    service_type "static"
    
    static_files {
        root "/var/www/app"
        fallback "index.html"  // Return index.html for all routes
        cache_control "public, max-age=3600"
        compress true
    }
}
```

### Security Considerations

- **Directory Traversal Protection**: Paths are validated to prevent access outside the root
- **Hidden Files**: Files starting with `.` are not served
- **Directory Listing**: Disabled by default for security
- **Content-Type Validation**: Automatic MIME type detection prevents XSS

## Performance Optimizations

### Web Service Type
- HTML minification (future feature)
- Automatic image optimization (future feature)
- Browser-specific optimizations

### API Service Type
- JSON streaming for large responses
- Request/response buffering control
- Connection pooling optimization

### Static Service Type
- In-memory caching for small files
- Sendfile support for large files
- Automatic compression for text files
- ETag generation and validation

## Best Practices

### 1. Choose the Right Service Type

- Use `web` for traditional server-rendered applications
- Use `api` for REST/GraphQL/RPC services
- Use `static` for CDN-like file serving

### 2. Configure Appropriate Error Pages

```kdl
// Web routes: user-friendly HTML
error_pages {
    default_format "html"
    template_dir "/etc/sentinel/error-templates"
}

// API routes: machine-readable JSON
error_pages {
    default_format "json"
    include_stack_trace false
}
```

### 3. Enable Schema Validation for APIs

```kdl
// Production: validate requests only
api_schema {
    validate_requests true
    validate_responses false
    strict_mode true
}

// Development: validate both
api_schema {
    validate_requests true
    validate_responses true
    strict_mode false
}
```

### 4. Optimize Static File Serving

```kdl
static_files {
    // Long cache for versioned assets
    cache_control "public, max-age=31536000, immutable"
    
    // Enable compression
    compress true
    
    // Custom types
    mime_types {
        "wasm" "application/wasm"
        "avif" "image/avif"
    }
}
```

### 5. Security Headers per Service Type

```kdl
// Web service
policies {
    response_headers {
        set {
            "X-Frame-Options" "SAMEORIGIN"
            "X-Content-Type-Options" "nosniff"
            "Content-Security-Policy" "default-src 'self'"
        }
    }
}

// API service
policies {
    response_headers {
        set {
            "X-Content-Type-Options" "nosniff"
            "Access-Control-Allow-Origin" "https://app.example.com"
        }
    }
}
```

## Migration Guide

### From Generic Routes to Service Types

Before:
```kdl
route "api" {
    upstream "backend"
    // Generic configuration
}
```

After:
```kdl
route "api" {
    service_type "api"
    upstream "backend"
    
    api_schema {
        schema_file "/etc/schemas/api.yaml"
        validate_requests true
    }
    
    error_pages {
        default_format "json"
    }
}
```

### From External Static Servers to Sentinel

Replace nginx/Apache static serving:

```kdl
route "assets" {
    service_type "static"
    upstream null  // No backend needed
    
    static_files {
        root "/var/www/html"
        directory_listing false
        compress true
    }
}
```

## Monitoring and Metrics

Service type specific metrics:

- **Web**: Page load times, session metrics
- **API**: Request validation failures, schema violations
- **Static**: Cache hit rates, file access patterns

Access metrics at `/metrics` endpoint:

```
sentinel_api_validation_failures{route="api-v1"} 42
sentinel_static_cache_hits{route="assets"} 10523
sentinel_static_cache_misses{route="assets"} 234
sentinel_error_pages_served{route="web-app",status="404",format="html"} 15
```

## Troubleshooting

### Common Issues

1. **API validation always fails**
   - Check schema file path and syntax
   - Verify content-type is `application/json`
   - Enable debug logging for validation details

2. **Static files return 404**
   - Verify root directory exists and is readable
   - Check file permissions
   - Review path resolution in logs

3. **Wrong error format returned**
   - Check route service_type configuration
   - Verify error_pages format setting
   - Check Accept header handling

### Debug Logging

Enable debug logging for service types:

```kdl
observability {
    logging {
        level "debug"
        modules {
            "sentinel::errors" "debug"
            "sentinel::static_files" "debug"
            "sentinel::validation" "debug"
        }
    }
}
```

## Future Enhancements

Planned features for service types:

- **GraphQL-specific handling** for `api` type
- **WebSocket support** for `web` type
- **Image optimization** for `static` type
- **Brotli compression** for all types
- **Request/response transformation** per service type
- **Service type specific rate limiting strategies**
- **Automatic OpenAPI documentation serving**