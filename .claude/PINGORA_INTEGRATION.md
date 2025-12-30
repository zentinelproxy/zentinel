# Pingora Framework Integration Opportunities

This document tracks Pingora features we should leverage but aren't yet using.

## Priority 1: Quick Wins

### 1. Use `pingora-timeout` for Efficient Timeouts
- **Status**: Dependency exists, not used
- **Impact**: 27x faster timeout operations
- **Effort**: Low
- **Location**: Replace `tokio::time::timeout` calls with `pingora_timeout::timeout`

### 2. Implement `connected_to_upstream()` Hook
- **Status**: Not implemented
- **Impact**: Connection reuse visibility, debugging
- **Effort**: Low
- **Details**: Log when connections are reused vs newly established

## Priority 2: WAF/Security Critical

### 3. Implement `request_body_filter()`
- **Status**: Not implemented
- **Impact**: Critical for WAF body inspection
- **Effort**: Medium
- **Details**: Process incoming request body chunks, enable body inspection for WAF agents

### 4. Implement `response_body_filter()`
- **Status**: Not implemented
- **Impact**: Critical for WAF response inspection
- **Effort**: Medium
- **Details**: Process upstream response body chunks, enable response body inspection

### 5. Integrate `pingora-limits` for Rate Limiting
- **Status**: Not used
- **Impact**: DoS protection, rate limiting
- **Effort**: Medium
- **Details**:
  - Count-Min Sketch for frequency estimation
  - Inflight request counting
  - Per-route rate limits

## Priority 3: Performance

### 6. Integrate `pingora-cache` for HTTP Caching
- **Status**: Not used
- **Impact**: Major performance improvement
- **Effort**: High
- **Details**:
  - Implement cache lifecycle methods (`cache_miss`, `cache_hit_filter`, etc.)
  - Cache-Control header parsing
  - Cache key generation
  - Stale-while-revalidate support

### 7. Enable HTTP/2 Support
- **Status**: Not enabled
- **Impact**: Better multiplexing, reduced latency
- **Effort**: Medium
- **Details**: Configure H2 for both downstream and upstream connections

### 8. Use `pingora-memory-cache` for Hot Data
- **Status**: Not used
- **Impact**: Reduce repeated computations
- **Effort**: Low-Medium
- **Details**: S3-FIFO + TinyLFU eviction, cache stampede protection

## Priority 4: Operational

### 9. Implement `upstream_request_filter()`
- **Status**: Not implemented
- **Impact**: Request modification before upstream
- **Effort**: Low
- **Details**: Modify headers, add authentication, etc.

### 10. Implement `fail_to_proxy()`
- **Status**: Not implemented
- **Impact**: Better error handling
- **Effort**: Low
- **Details**: Custom error pages for fatal proxy errors

### 11. Implement `range_header_filter()`
- **Status**: Not implemented
- **Impact**: Video/large file streaming
- **Effort**: Medium
- **Details**: Handle byte-range requests properly

### 12. Add Service Discovery Integration
- **Status**: Not used
- **Impact**: Dynamic backend discovery
- **Effort**: Medium
- **Details**: Use `pingora-load-balancing` service discovery traits

## Not Using (Lower Priority)

- `suppress_error_log()` - Control error logging granularity
- `request_summary()` - Enhanced error log context
- `init_downstream_modules()` - HTTP module configuration
- `proxy_upstream_filter()` - Post-cache-miss filtering
- `response_trailer_filter()` - HTTP trailer handling
- `upstream_response_trailer_filter()` - Upstream trailer handling

## ProxyHttp Methods Reference

Currently implemented (7):
- `new_ctx()`
- `early_request_filter()`
- `upstream_peer()`
- `request_filter()`
- `response_filter()`
- `fail_to_connect()`
- `logging()`

Not implemented (25+):
- Body filters (request/response)
- Cache lifecycle (10+ methods)
- Connection hooks
- Error handling hooks
- Range/trailer filters

## Progress Tracking

- [x] 1. pingora-timeout integration (2024-12-30)
- [x] 2. connected_to_upstream() hook (2024-12-30)
- [x] 3. request_body_filter() (2024-12-30)
- [x] 4. response_body_filter() (2024-12-30)
- [x] 5. pingora-limits rate limiting (2024-12-30)
- [x] 6. pingora-cache HTTP caching infrastructure (2024-12-30)
  - Note: Core infrastructure implemented (CacheConfig, CacheManager, statistics)
  - ProxyHttp cache methods pending pingora-cache API stabilization
- [x] 7. HTTP/2 support (2024-12-30)
  - HttpVersionConfig for upstream configuration (min/max version, H2 ping interval, max streams)
  - ALPN negotiation (H2, H2H1, H1) based on configuration
  - TLS SNI configuration for upstream connections
  - KDL parsing for http-version block
- [x] 8. pingora-memory-cache (2024-12-30)
  - MemoryCacheManager for route matching cache
  - TypedCache<K,V> generic wrapper for arbitrary types
  - S3-FIFO + TinyLFU eviction via pingora-memory-cache
  - Cache statistics (hits, misses, insertions)
- [x] 9. upstream_request_filter() (2024-12-30)
- [x] 10. fail_to_proxy() (2024-12-30)
- [x] 11. range_header_filter() (2024-12-30)
  - Route-based range request support (static/web routes)
  - Logging for single-range, multi-range, and invalid range requests
  - Uses Pingora's built-in RFC7232 compliant implementation
- [x] 12. Service discovery (2024-12-30)
  - DiscoveryManager for managing upstream service discovery
  - Static discovery (fixed backend list)
  - DNS-based discovery with caching and refresh intervals
  - ServiceDiscovery trait integration with pingora-load-balancing
