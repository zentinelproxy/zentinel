-- name: Request Header Manipulation Example
-- version: 1.0.0
-- author: Sentinel Team
-- description: Example script showing request header manipulation capabilities
-- hook: request_headers
-- processing: streaming
-- paths: /api/*, /v1/*
-- methods: GET, POST, PUT, DELETE
-- priority: 100
-- requires: json, http, string_ext

-- This script demonstrates various request header manipulation techniques
-- It runs at the request_headers phase before the request is sent upstream

function on_request_headers()
    -- Access the global request object
    local method = request.method
    local path = request.path
    local headers = request.headers

    -- Log the incoming request
    sentinel.log("info", string.format("Processing %s %s", method, path))

    -- Example 1: Add a request ID if not present
    if not headers["X-Request-Id"] then
        local request_id = crypto.random_hex(16)
        add_header("X-Request-Id", request_id)
        sentinel.add_metadata("request_id", request_id)
    end

    -- Example 2: Add timestamp header
    local timestamp = tostring(time.now_ms())
    add_header("X-Timestamp", timestamp)

    -- Example 3: Parse and validate API key
    local api_key = headers["X-API-Key"]
    if api_key then
        -- Validate API key format (example: must be 32 characters)
        if string.len(api_key) ~= 32 then
            sentinel.log("warn", "Invalid API key length")
            sentinel.set_decision("deny")
            sentinel.add_metadata("reason", "invalid_api_key_format")
            return {
                decision = "deny",
                status = 401,
                body = json.encode({
                    error = "Invalid API key format"
                })
            }
        end

        -- Add API key hash for logging (don't log the actual key)
        local key_hash = crypto.sha256(api_key)
        add_header("X-API-Key-Hash", string.sub(key_hash, 1, 8))
    end

    -- Example 4: User agent parsing and device detection
    local user_agent = headers["User-Agent"] or ""
    local device_type = "unknown"

    if string_ext.contains(user_agent, "Mobile") then
        device_type = "mobile"
    elseif string_ext.contains(user_agent, "Tablet") then
        device_type = "tablet"
    elseif string_ext.contains(user_agent, "Bot") or string_ext.contains(user_agent, "bot") then
        device_type = "bot"
        -- Block bots if needed
        if path:match("^/api/private") then
            sentinel.set_decision("deny")
            return {
                decision = "deny",
                status = 403,
                body = "Bots not allowed"
            }
        end
    else
        device_type = "desktop"
    end

    add_header("X-Device-Type", device_type)

    -- Example 5: JWT token extraction and validation
    local auth_header = headers["Authorization"]
    if auth_header and string_ext.starts_with(auth_header, "Bearer ") then
        local token = string.sub(auth_header, 8)

        -- Decode JWT (without verification - just for claims extraction)
        -- In production, use a proper JWT library or the auth agent
        local parts = string_ext.split(token, ".")
        if #parts == 3 then
            -- Decode the payload (second part)
            local payload = encoding.base64_decode(parts[2])
            if payload then
                local claims = json.decode(payload)
                if claims then
                    -- Add user information to headers
                    if claims.sub then
                        add_header("X-User-Id", claims.sub)
                    end
                    if claims.email then
                        add_header("X-User-Email", claims.email)
                    end
                    if claims.roles then
                        add_header("X-User-Roles", table.concat(claims.roles, ","))
                    end

                    -- Check token expiration
                    if claims.exp and claims.exp < time.now() then
                        sentinel.set_decision("deny")
                        return {
                            decision = "deny",
                            status = 401,
                            body = json.encode({
                                error = "Token expired"
                            })
                        }
                    end
                end
            end
        end
    end

    -- Example 6: Rate limiting headers
    local client_ip = headers["X-Real-IP"] or headers["X-Forwarded-For"]
    if client_ip then
        -- Clean up X-Forwarded-For (take first IP if multiple)
        if string_ext.contains(client_ip, ",") then
            local ips = string_ext.split(client_ip, ",")
            client_ip = string_ext.trim(ips[1])
        end
        add_header("X-Client-IP", client_ip)

        -- Add rate limit key
        local rate_limit_key = crypto.sha256(client_ip .. ":" .. (api_key or "anonymous"))
        add_header("X-Rate-Limit-Key", rate_limit_key)
    end

    -- Example 7: Content negotiation
    local accept = headers["Accept"] or "application/json"
    local response_format = "json"

    if string_ext.contains(accept, "application/xml") then
        response_format = "xml"
    elseif string_ext.contains(accept, "text/html") then
        response_format = "html"
    elseif string_ext.contains(accept, "application/yaml") then
        response_format = "yaml"
    end

    add_header("X-Response-Format", response_format)

    -- Example 8: CORS headers for specific origins
    local origin = headers["Origin"]
    if origin then
        local allowed_origins = {
            "https://app.example.com",
            "https://staging.example.com",
            "http://localhost:3000"
        }

        for _, allowed in ipairs(allowed_origins) do
            if origin == allowed then
                add_header("X-CORS-Allowed", "true")
                break
            end
        end
    end

    -- Example 9: Request context enrichment
    local context = {
        timestamp = timestamp,
        method = method,
        path = path,
        device = device_type,
        has_auth = auth_header ~= nil,
        client_ip = client_ip
    }

    -- Encode context as header for upstream service
    add_header("X-Request-Context", encoding.base64_encode(json.encode(context)))

    -- Example 10: Conditional header removal
    -- Remove sensitive headers that shouldn't go to upstream
    local sensitive_headers = {
        "Cookie",
        "X-Internal-Secret",
        "X-Debug-Token"
    }

    for _, header_name in ipairs(sensitive_headers) do
        if headers[header_name] then
            remove_header(header_name)
            sentinel.log("debug", "Removed sensitive header: " .. header_name)
        end
    end

    -- Example 11: Path rewriting based on headers
    if headers["X-API-Version"] == "v2" then
        -- Rewrite v1 paths to v2
        if string_ext.starts_with(path, "/api/v1/") then
            local new_path = string_ext.replace(path, "/api/v1/", "/api/v2/")
            set_path(new_path)
            sentinel.log("info", "Rewrote path from " .. path .. " to " .. new_path)
        end
    end

    -- Example 12: Add tracing headers
    local trace_id = headers["X-Trace-Id"] or crypto.random_hex(16)
    local span_id = crypto.random_hex(8)

    add_header("X-Trace-Id", trace_id)
    add_header("X-Span-Id", span_id)
    add_header("X-Parent-Span-Id", headers["X-Span-Id"] or "root")

    -- Store trace information in metadata
    sentinel.add_metadata("trace_id", trace_id)
    sentinel.add_metadata("span_id", span_id)

    -- Return the mutations to be applied
    return {
        -- Headers are already added via add_header() calls
        -- But we can return additional mutations here
        add_header = {
            {name = "X-Processed-By", value = "lua-agent"},
            {name = "X-Script-Version", value = "1.0.0"}
        },

        -- We can also set the decision here
        -- (default is "allow" if not set)
        decision = "allow"
    }
end

-- Helper function to add a header
function add_header(name, value)
    if not _G.headers_to_add then
        _G.headers_to_add = {}
    end
    table.insert(_G.headers_to_add, {name = name, value = value})
end

-- Helper function to remove a header
function remove_header(name)
    if not _G.headers_to_remove then
        _G.headers_to_remove = {}
    end
    table.insert(_G.headers_to_remove, name)
end

-- Helper function to set the path
function set_path(path)
    _G.new_path = path
end
