# Sentinel Lua Scripting Agent

A powerful and secure Lua scripting agent for Sentinel that enables custom request/response processing with support for streaming, chunked transfers, and hot reload.

## Features

### 🚀 Core Capabilities
- **Flexible Hook System**: Process requests/responses at different phases
- **Streaming & Buffered Processing**: Handle both chunked and full-body content
- **Hot Reload**: Update scripts without restarting the agent
- **Sandboxed Execution**: Secure script execution with resource limits
- **Rich Standard Library**: JSON, crypto, HTTP utilities, and more
- **Performance**: VM pooling and bytecode caching for optimal performance

### 🔒 Security
- **Resource Limits**: Memory, CPU, and execution time constraints
- **Sandboxing**: Restricted access to system resources
- **Safe Defaults**: Dangerous functions removed by default
- **Fail-Safe Options**: Configure fail-open or fail-closed behavior

### 📊 Observability
- **Comprehensive Metrics**: Request processing, script execution, and performance metrics
- **Structured Logging**: JSON logs with correlation IDs
- **Script Debugging**: Debug mode for development

## Installation

### Building from Source
```bash
cd agents/lua-agent
cargo build --release
```

### Docker
```bash
docker build -t sentinel-lua-agent .
docker run -v /path/to/scripts:/scripts sentinel-lua-agent
```

## Configuration

### Basic Configuration (KDL)
```kdl
// config/lua-agent.kdl
socket-path "/var/run/sentinel/lua-agent.sock"

scripts {
    directory "/etc/sentinel/scripts"
    hot-reload true
    watch-interval 5
    timeout 50  // milliseconds
    cache-size 100
    cache-ttl 60
}

vm-pool {
    size 10
    max-age 300
    max-executions 1000
}

resource-limits {
    max-memory 52428800        // 50MB
    max-instructions 10000000  // 10M
    max-execution-time 100     // ms
    max-string-length 10485760 // 10MB
    max-table-size 10000
    allow-filesystem false
    allow-network false
    
    allowed-library "string"
    allowed-library "table"
    allowed-library "math"
    allowed-library "utf8"
}

safety {
    fail-open false
    debug-scripts false
    max-concurrent 100
}
```

## Writing Lua Scripts

### Script Metadata
Scripts should include metadata in comments at the top:

```lua
-- name: My Script
-- version: 1.0.0
-- author: Your Name
-- description: What this script does
-- hook: request_headers | request_body | response_headers | response_body | complete
-- processing: streaming | buffered | auto
-- paths: /api/*, /v1/*
-- methods: GET, POST, PUT, DELETE
-- priority: 100  (lower numbers run first)
-- requires: json, http, crypto
```

### Available Hooks

#### 1. Request Headers Hook
```lua
function on_request_headers()
    -- Access request information
    local method = request.method
    local path = request.path
    local headers = request.headers
    
    -- Add a header
    request.headers["X-Custom-Header"] = "value"
    
    -- Remove a header
    request.headers["Cookie"] = nil
    
    -- Modify the path
    request.path = "/new/path"
    
    -- Return decision
    return {
        decision = "allow",  -- or "deny" or "challenge"
        add_header = {
            {name = "X-Added", value = "true"}
        },
        remove_header = {"X-Remove-Me"}
    }
end
```

#### 2. Request Body Hook (Streaming)
```lua
function on_request_body_chunk(chunk)
    -- Process each chunk as it arrives
    local modified = transform_chunk(chunk)
    
    -- Return modified chunk or nil to drop
    return modified
end
```

#### 3. Request Body Hook (Buffered)
```lua
function on_request_body(body)
    -- Process complete body
    local data = json.decode(body)
    
    -- Modify data
    data.processed = true
    
    -- Return modified body
    return json.encode(data)
end
```

#### 4. Response Headers Hook
```lua
function on_response_headers()
    local status = response.status
    local headers = response.headers
    
    -- Add security headers
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "DENY"
    
    -- Modify status
    if status == 404 then
        response.status = 200
    end
    
    return {decision = "allow"}
end
```

#### 5. Response Body Hook
```lua
function on_response_body(body)
    -- Transform response
    local data = json.decode(body)
    data._metadata = {
        processed_at = time.now(),
        version = "1.0"
    }
    return json.encode(data)
end
```

#### 6. Complete Hook
```lua
function on_complete()
    -- Access both request and response
    sentinel.log("info", string.format(
        "%s %s -> %d",
        request.method,
        request.path,
        response.status
    ))
    
    return {decision = "allow"}
end
```

## Standard Library

### JSON Module
```lua
-- Encode/decode JSON
local data = {key = "value", number = 42}
local json_str = json.encode(data)
local decoded = json.decode(json_str)
local pretty = json.encode_pretty(data)
```

### Crypto Module
```lua
-- Hashing
local hash = crypto.sha256("data")
local hash384 = crypto.sha384("data")
local hash512 = crypto.sha512("data")

-- HMAC
local hmac = crypto.hmac_sha256("key", "message")

-- Random data
local random_bytes = crypto.random_bytes(16)
local random_hex = crypto.random_hex(32)
```

### HTTP Module
```lua
-- URL encoding
local encoded = http.url_encode("hello world")
local decoded = http.url_decode("hello%20world")

-- Query string parsing
local params = http.parse_query("foo=bar&baz=qux")
local query = http.build_query({foo = "bar", baz = "qux"})

-- Cookie parsing
local cookies = http.parse_cookies("session=abc123; theme=dark")

-- Status text
local text = http.status_text(404)  -- "Not Found"
```

### Encoding Module
```lua
-- Base64
local b64 = encoding.base64_encode("hello")
local decoded = encoding.base64_decode(b64)

-- Hex
local hex = encoding.hex_encode("hello")
local decoded = encoding.hex_decode(hex)

-- Compression
local compressed = encoding.gzip_compress("large text")
local decompressed = encoding.gzip_decompress(compressed)
```

### String Extensions
```lua
-- String utilities
local parts = string_ext.split("a,b,c", ",")
local trimmed = string_ext.trim("  hello  ")
local starts = string_ext.starts_with("hello", "he")
local ends = string_ext.ends_with("hello", "lo")
local contains = string_ext.contains("hello world", "world")
local replaced = string_ext.replace("hello", "l", "L")
```

### Regex Module
```lua
-- Pattern matching
local matches = regex.match("^hello", "hello world")
local found = regex.find("\\d+", "test 123 abc")
local all = regex.find_all("\\w+", "hello world")
local replaced = regex.replace("\\d+", "test 123", "XXX")
```

### Time Module
```lua
-- Timestamps
local now = time.now()           -- Unix timestamp
local now_ms = time.now_ms()     -- Milliseconds
local formatted = time.format(now, "%Y-%m-%d %H:%M:%S")
local parsed = time.parse("2024-01-01", "%Y-%m-%d")
```

### Sentinel Module
```lua
-- Logging
sentinel.log("info", "Processing request")
sentinel.log("warn", "Unusual pattern detected")
sentinel.log("error", "Failed to process")

-- Set decision
sentinel.set_decision("allow")  -- or "deny" or "challenge"

-- Add metadata
sentinel.add_metadata("key", "value")
```

## Advanced Examples

### Rate Limiting with Distributed Counter
```lua
function on_request_headers()
    local client_ip = request.headers["X-Real-IP"] or "unknown"
    local key = crypto.sha256(client_ip)
    
    -- Store in metadata for rate limit agent
    request.headers["X-Rate-Limit-Key"] = key
    
    -- Check custom rate limit
    local minute = math.floor(time.now() / 60)
    local counter_key = key .. ":" .. minute
    
    -- This would integrate with Redis or similar
    -- local count = redis.incr(counter_key)
    -- if count > 100 then
    --     return {decision = "deny", status = 429}
    -- end
    
    return {decision = "allow"}
end
```

### Dynamic Response Transformation
```lua
function on_response_body()
    local content_type = response.headers["Content-Type"] or ""
    
    if string_ext.contains(content_type, "application/json") then
        local data = json.decode(response.body)
        
        -- Add metadata
        data._meta = {
            server = "sentinel",
            timestamp = time.now_ms(),
            request_id = request.headers["X-Request-Id"]
        }
        
        -- Filter sensitive fields
        if data.user then
            data.user.password = nil
            data.user.ssn = nil
        end
        
        return json.encode_pretty(data)
    end
    
    return response.body
end
```

### A/B Testing Router
```lua
function on_request_headers()
    local user_id = request.headers["X-User-Id"]
    
    if user_id then
        -- Consistent hashing for A/B test assignment
        local hash = crypto.sha256(user_id .. "experiment-1")
        local bucket = tonumber("0x" .. string.sub(hash, 1, 8)) % 100
        
        if bucket < 20 then  -- 20% to experiment
            request.headers["X-Experiment"] = "variant-a"
            request.path = "/v2" .. request.path
        else
            request.headers["X-Experiment"] = "control"
        end
    end
    
    return {decision = "allow"}
end
```

## Performance Optimization

### 1. Use Streaming for Large Bodies
```lua
-- Good: Process chunks as they arrive
function on_request_body_chunk(chunk)
    return process_chunk(chunk)
end

-- Avoid: Buffering entire large bodies
function on_request_body()
    -- This loads entire body into memory
    return process_body(request.body)
end
```

### 2. Cache Expensive Operations
```lua
local cache = {}

function expensive_operation(key)
    if cache[key] then
        return cache[key]
    end
    
    local result = -- expensive computation
    cache[key] = result
    return result
end
```

### 3. Minimize String Operations
```lua
-- Good: Use table.concat for multiple strings
local parts = {}
for i = 1, 1000 do
    table.insert(parts, "item" .. i)
end
local result = table.concat(parts, ",")

-- Avoid: String concatenation in loops
local result = ""
for i = 1, 1000 do
    result = result .. "item" .. i .. ","
end
```

## Troubleshooting

### Script Not Loading
1. Check script metadata format
2. Verify file has `.lua` extension
3. Check logs for syntax errors
4. Ensure script directory is readable

### Performance Issues
1. Enable metrics to identify slow scripts
2. Use streaming mode for large bodies
3. Reduce VM pool size if memory is constrained
4. Check resource limits in configuration

### Debugging Scripts
1. Enable debug mode in configuration
2. Use `sentinel.log()` liberally
3. Test scripts in isolation first
4. Use the script validator tool

## Security Best Practices

1. **Never log sensitive data**: Hash or redact before logging
2. **Validate all inputs**: Don't trust request data
3. **Use fail-closed mode**: For security-critical scripts
4. **Set appropriate timeouts**: Prevent runaway scripts
5. **Limit resource usage**: Configure memory and CPU limits
6. **Audit script changes**: Use version control
7. **Test in staging**: Always test scripts before production

## Metrics and Monitoring

The Lua agent exposes the following metrics:

- `lua_agent_requests_total`: Total requests processed
- `lua_agent_script_executions_total`: Script executions by script name
- `lua_agent_script_errors_total`: Script execution errors
- `lua_agent_script_timeouts_total`: Script timeouts
- `lua_agent_processing_duration_seconds`: Script execution time
- `lua_agent_vm_pool_size`: Current VM pool size
- `lua_agent_vm_recreations_total`: VM recreations due to limits

## Support

For issues, feature requests, or questions:
- GitHub Issues: https://github.com/sentinel-rs/sentinel
- Documentation: https://docs.sentinel.rs
- Community: https://discord.gg/sentinel

## License

Apache-2.0