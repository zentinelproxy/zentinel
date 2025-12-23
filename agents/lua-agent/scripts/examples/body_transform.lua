-- name: Body Transform Example
-- version: 1.0.0
-- author: Sentinel Team
-- description: Example script showing request/response body transformation with chunked processing
-- hook: complete
-- processing: auto
-- paths: /api/transform/*, /webhook/*
-- methods: POST, PUT, PATCH
-- priority: 90
-- requires: json, encoding, crypto, string_ext

-- This script demonstrates body transformation capabilities
-- It can work with both streaming (chunk-by-chunk) and buffered (full body) modes

-- Configuration
local MAX_BODY_SIZE = 10 * 1024 * 1024  -- 10MB
local CHUNK_SIZE = 8192  -- 8KB chunks for streaming

-- State for chunked processing
local request_chunks = {}
local response_chunks = {}
local is_json_request = false
local is_json_response = false

-- Initialize the script
function init()
    sentinel.log("debug", "Body transform script initialized")
end

-- Process request headers to determine body handling
function on_request_headers()
    local content_type = request.headers["Content-Type"] or ""
    local content_length = tonumber(request.headers["Content-Length"] or "0")

    -- Determine if we need to buffer or stream
    is_json_request = string_ext.contains(content_type, "application/json")

    -- Check body size
    if content_length > MAX_BODY_SIZE then
        sentinel.log("warn", "Request body too large: " .. content_length)
        sentinel.set_decision("deny")
        return {
            decision = "deny",
            status = 413,
            body = json.encode({
                error = "Request body too large",
                max_size = MAX_BODY_SIZE
            })
        }
    end

    -- Add processing headers
    request.headers["X-Body-Processing"] = is_json_request and "json" or "passthrough"
    request.headers["X-Original-Size"] = tostring(content_length)

    return {decision = "allow"}
end

-- Process request body chunks (streaming mode)
function on_request_body_chunk(chunk)
    local chunk_size = string.len(chunk)
    sentinel.log("debug", "Processing request chunk: " .. chunk_size .. " bytes")

    -- Store chunk for later processing if needed
    table.insert(request_chunks, chunk)

    -- Example: Redact sensitive data in JSON chunks
    if is_json_request then
        -- Try to detect and redact patterns even in chunks
        chunk = redact_sensitive_patterns(chunk)
    end

    -- Example: Compress large text chunks
    if chunk_size > CHUNK_SIZE then
        local compressed = encoding.gzip_compress(chunk)
        if string.len(compressed) < chunk_size * 0.8 then
            sentinel.log("info", "Compressed chunk from " .. chunk_size .. " to " .. string.len(compressed))
            -- Note: You'd need to handle decompression on the other end
            -- chunk = compressed
        end
    end

    -- Example: Calculate running hash for integrity
    if not _G.request_hash then
        _G.request_hash = ""
    end
    _G.request_hash = crypto.sha256(_G.request_hash .. chunk)

    return chunk  -- Return modified chunk
end

-- Process complete request body (buffered mode)
function on_request_body()
    -- Combine all chunks if we have them
    local full_body = table.concat(request_chunks)

    sentinel.log("info", "Processing complete request body: " .. string.len(full_body) .. " bytes")

    -- Example 1: JSON transformation
    if is_json_request and full_body ~= "" then
        local success, data = pcall(json.decode, full_body)
        if success and data then
            -- Transform the JSON data
            data = transform_json_request(data)

            -- Re-encode
            full_body = json.encode(data)

            -- Update content length
            request.headers["Content-Length"] = tostring(string.len(full_body))
        else
            sentinel.log("warn", "Failed to parse JSON body")
        end
    end

    -- Example 2: Add signature
    local signature = crypto.hmac_sha256("secret-key", full_body)
    request.headers["X-Body-Signature"] = signature

    -- Example 3: Log body hash for audit
    local body_hash = crypto.sha256(full_body)
    sentinel.add_metadata("request_body_hash", body_hash)

    return full_body
end

-- Process response headers
function on_response_headers()
    local content_type = response.headers["Content-Type"] or ""
    local status = response.status

    is_json_response = string_ext.contains(content_type, "application/json")

    -- Add processing headers
    response.headers["X-Response-Processed"] = "true"
    response.headers["X-Processing-Time"] = tostring(time.now_ms())

    -- Example: Add security headers
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "DENY"

    return {decision = "allow"}
end

-- Process response body chunks (streaming mode)
function on_response_body_chunk(chunk)
    local chunk_size = string.len(chunk)
    sentinel.log("debug", "Processing response chunk: " .. chunk_size .. " bytes")

    -- Store for potential buffering
    table.insert(response_chunks, chunk)

    -- Example: Stream processing for HTML responses
    if string_ext.contains(response.headers["Content-Type"] or "", "text/html") then
        -- Inject tracking script or modify HTML on the fly
        chunk = inject_html_modifications(chunk)
    end

    -- Example: Real-time data masking
    if is_json_response then
        chunk = mask_json_fields_streaming(chunk)
    end

    return chunk
end

-- Process complete response body (buffered mode)
function on_response_body()
    local full_body = table.concat(response_chunks)

    sentinel.log("info", "Processing complete response body: " .. string.len(full_body) .. " bytes")

    -- Example 1: JSON response transformation
    if is_json_response and full_body ~= "" then
        local success, data = pcall(json.decode, full_body)
        if success and data then
            -- Transform response
            data = transform_json_response(data)

            -- Add metadata
            data._metadata = {
                processed_at = time.now(),
                processor = "lua-agent",
                request_id = request.headers["X-Request-Id"]
            }

            full_body = json.encode_pretty(data)
            response.headers["Content-Length"] = tostring(string.len(full_body))
        end
    end

    -- Example 2: Response caching headers
    if response.status == 200 then
        response.headers["Cache-Control"] = "public, max-age=300"
        response.headers["ETag"] = '"' .. crypto.sha256(full_body):sub(1, 16) .. '"'
    end

    return full_body
end

-- Transform JSON request data
function transform_json_request(data)
    -- Example: Add timestamp to all requests
    if type(data) == "table" then
        data.processed_at = time.now()
        data.processor_version = "1.0.0"

        -- Example: Validate required fields
        if data.user_id == nil then
            data.user_id = "anonymous"
        end

        -- Example: Normalize phone numbers
        if data.phone then
            data.phone = normalize_phone(data.phone)
        end

        -- Example: Encrypt sensitive fields
        if data.ssn then
            data.ssn = encrypt_field(data.ssn)
            data.ssn_encrypted = true
        end
    end

    return data
end

-- Transform JSON response data
function transform_json_response(data)
    -- Example: Remove internal fields
    if type(data) == "table" then
        data.internal_id = nil
        data._debug = nil

        -- Example: Add calculated fields
        if data.items and type(data.items) == "table" then
            data.total_count = #data.items
        end

        -- Example: Format dates
        if data.created_at then
            data.created_at_formatted = time.format(data.created_at, "%Y-%m-%d %H:%M:%S")
        end
    end

    return data
end

-- Redact sensitive patterns in text
function redact_sensitive_patterns(text)
    -- Credit card numbers
    text = regex.replace([[\b\d{4}[\s-]?\d{4}[\s-]?\d{4}[\s-]?\d{4}\b]], text, "****-****-****-****")

    -- SSN
    text = regex.replace([[\b\d{3}-\d{2}-\d{4}\b]], text, "***-**-****")

    -- Email addresses (partial redaction)
    text = regex.replace([[\b([a-zA-Z0-9._%+-]+)@([a-zA-Z0-9.-]+\.[a-zA-Z]{2,})\b]],
                         text,
                         function(match)
                             local parts = string_ext.split(match, "@")
                             if #parts == 2 then
                                 local name = parts[1]
                                 if string.len(name) > 2 then
                                     name = string.sub(name, 1, 2) .. "****"
                                 end
                                 return name .. "@" .. parts[2]
                             end
                             return match
                         end)

    return text
end

-- Inject HTML modifications
function inject_html_modifications(chunk)
    -- Example: Add tracking script before </body>
    if string_ext.contains(chunk, "</body>") then
        local tracking_script = [[
            <script>
                console.log('Page processed by Sentinel');
                window._sentinel = {version: '1.0.0', timestamp: ]] .. time.now_ms() .. [[};
            </script>
        ]]
        chunk = string_ext.replace(chunk, "</body>", tracking_script .. "</body>")
    end

    return chunk
end

-- Mask JSON fields in streaming mode
function mask_json_fields_streaming(chunk)
    -- This is simplified - in production you'd need proper JSON streaming parser
    local sensitive_fields = {"password", "token", "secret", "api_key"}

    for _, field in ipairs(sensitive_fields) do
        -- Look for patterns like "field": "value"
        local pattern = '"' .. field .. '"\\s*:\\s*"[^"]*"'
        chunk = regex.replace(pattern, chunk, '"' .. field .. '": "***REDACTED***"')
    end

    return chunk
end

-- Normalize phone number
function normalize_phone(phone)
    -- Remove all non-digits
    phone = regex.replace([[\D]], phone, "")

    -- Format as US phone if 10 digits
    if string.len(phone) == 10 then
        return string.format("(%s) %s-%s",
            string.sub(phone, 1, 3),
            string.sub(phone, 4, 6),
            string.sub(phone, 7, 10))
    end

    return phone
end

-- Simple encryption (in production, use proper encryption)
function encrypt_field(value)
    -- This is just an example - use proper encryption in production
    return encoding.base64_encode(crypto.sha256(value .. "salt"))
end

-- Main entry point for complete hook
function on_complete()
    sentinel.log("info", "Request/response processing complete")

    -- Final metrics
    local metrics = {
        request_chunks = #request_chunks,
        response_chunks = #response_chunks,
        total_request_size = 0,
        total_response_size = 0
    }

    for _, chunk in ipairs(request_chunks) do
        metrics.total_request_size = metrics.total_request_size + string.len(chunk)
    end

    for _, chunk in ipairs(response_chunks) do
        metrics.total_response_size = metrics.total_response_size + string.len(chunk)
    end

    sentinel.add_metadata("processing_metrics", json.encode(metrics))

    return {decision = "allow"}
end
