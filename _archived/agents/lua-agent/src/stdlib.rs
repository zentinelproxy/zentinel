//! Lua standard library extensions for Sentinel scripts
//!
//! This module provides safe and useful functions for Lua scripts including
//! JSON handling, crypto operations, HTTP utilities, and more.

use anyhow::{anyhow, Result};
use base64::{engine::general_purpose::STANDARD as BASE64, Engine};
use chrono::{DateTime, Utc};
use flate2::read::{GzDecoder, ZlibDecoder};
use flate2::write::{GzEncoder, ZlibEncoder};
use flate2::Compression;
use hmac::{Hmac, Mac};
use mlua::prelude::*;
use percent_encoding::{percent_decode_str, percent_encode, NON_ALPHANUMERIC};
use regex::Regex;
use serde_json::{self, Value as JsonValue};
use sha2::{Digest, Sha256, Sha384, Sha512};
use std::collections::HashMap;
use std::io::{Read, Write};
use std::str;
use tracing::{debug, warn};

/// Load standard library extensions into Lua
pub struct LuaStdLib;

impl LuaStdLib {
    /// Load all standard library modules
    pub fn load(lua: &Lua) -> Result<()> {
        Self::load_json(lua)?;
        Self::load_crypto(lua)?;
        Self::load_http(lua)?;
        Self::load_encoding(lua)?;
        Self::load_string_ext(lua)?;
        Self::load_regex(lua)?;
        Self::load_time(lua)?;
        Self::load_sentinel(lua)?;

        debug!("Loaded Lua standard library extensions");
        Ok(())
    }

    /// Load JSON module
    fn load_json(lua: &Lua) -> Result<()> {
        let json_module = lua.create_table()?;

        // json.encode(value) -> string
        let encode_fn = lua.create_function(|lua, value: LuaValue| {
            let json_value = lua_to_json(value)?;
            match serde_json::to_string(&json_value) {
                Ok(json_str) => Ok(json_str),
                Err(e) => Err(LuaError::RuntimeError(format!("JSON encode error: {}", e))),
            }
        })?;
        json_module.set("encode", encode_fn)?;

        // json.decode(string) -> value
        let decode_fn = lua.create_function(|lua, json_str: String| {
            match serde_json::from_str::<JsonValue>(&json_str) {
                Ok(json_value) => json_to_lua(lua, json_value),
                Err(e) => Err(LuaError::RuntimeError(format!("JSON decode error: {}", e))),
            }
        })?;
        json_module.set("decode", decode_fn)?;

        // json.encode_pretty(value) -> string
        let encode_pretty_fn = lua.create_function(|lua, value: LuaValue| {
            let json_value = lua_to_json(value)?;
            match serde_json::to_string_pretty(&json_value) {
                Ok(json_str) => Ok(json_str),
                Err(e) => Err(LuaError::RuntimeError(format!("JSON encode error: {}", e))),
            }
        })?;
        json_module.set("encode_pretty", encode_pretty_fn)?;

        lua.globals().set("json", json_module)?;
        Ok(())
    }

    /// Load crypto module
    fn load_crypto(lua: &Lua) -> Result<()> {
        let crypto_module = lua.create_table()?;

        // crypto.sha256(data) -> hex string
        let sha256_fn = lua.create_function(|_, data: LuaString| {
            let mut hasher = Sha256::new();
            hasher.update(data.as_bytes());
            Ok(hex::encode(hasher.finalize()))
        })?;
        crypto_module.set("sha256", sha256_fn)?;

        // crypto.sha384(data) -> hex string
        let sha384_fn = lua.create_function(|_, data: LuaString| {
            let mut hasher = Sha384::new();
            hasher.update(data.as_bytes());
            Ok(hex::encode(hasher.finalize()))
        })?;
        crypto_module.set("sha384", sha384_fn)?;

        // crypto.sha512(data) -> hex string
        let sha512_fn = lua.create_function(|_, data: LuaString| {
            let mut hasher = Sha512::new();
            hasher.update(data.as_bytes());
            Ok(hex::encode(hasher.finalize()))
        })?;
        crypto_module.set("sha512", sha512_fn)?;

        // crypto.hmac_sha256(key, data) -> hex string
        let hmac_sha256_fn = lua.create_function(|_, (key, data): (LuaString, LuaString)| {
            type HmacSha256 = Hmac<Sha256>;
            let mut mac = HmacSha256::new_from_slice(key.as_bytes())
                .map_err(|e| LuaError::RuntimeError(format!("HMAC error: {}", e)))?;
            mac.update(data.as_bytes());
            Ok(hex::encode(mac.finalize().into_bytes()))
        })?;
        crypto_module.set("hmac_sha256", hmac_sha256_fn)?;

        // crypto.random_bytes(length) -> string
        let random_bytes_fn = lua.create_function(|_, length: usize| {
            if length > 1024 {
                return Err(LuaError::RuntimeError(
                    "Random bytes length too large (max 1024)".to_string(),
                ));
            }
            let mut bytes = vec![0u8; length];
            use rand::RngCore;
            rand::thread_rng().fill_bytes(&mut bytes);
            Ok(bytes)
        })?;
        crypto_module.set("random_bytes", random_bytes_fn)?;

        // crypto.random_hex(length) -> hex string
        let random_hex_fn = lua.create_function(|_, length: usize| {
            if length > 512 {
                return Err(LuaError::RuntimeError(
                    "Random hex length too large (max 512)".to_string(),
                ));
            }
            let mut bytes = vec![0u8; length];
            use rand::RngCore;
            rand::thread_rng().fill_bytes(&mut bytes);
            Ok(hex::encode(bytes))
        })?;
        crypto_module.set("random_hex", random_hex_fn)?;

        lua.globals().set("crypto", crypto_module)?;
        Ok(())
    }

    /// Load HTTP utilities module
    fn load_http(lua: &Lua) -> Result<()> {
        let http_module = lua.create_table()?;

        // http.url_encode(string) -> string
        let url_encode_fn = lua.create_function(|_, text: String| {
            Ok(percent_encode(text.as_bytes(), NON_ALPHANUMERIC).to_string())
        })?;
        http_module.set("url_encode", url_encode_fn)?;

        // http.url_decode(string) -> string
        let url_decode_fn = lua.create_function(|_, text: String| {
            percent_decode_str(&text)
                .decode_utf8()
                .map(|s| s.to_string())
                .map_err(|e| LuaError::RuntimeError(format!("URL decode error: {}", e)))
        })?;
        http_module.set("url_decode", url_decode_fn)?;

        // http.parse_query(query_string) -> table
        let parse_query_fn = lua.create_function(|lua, query: String| {
            let result = lua.create_table()?;
            for pair in query.split('&') {
                if let Some((key, value)) = pair.split_once('=') {
                    let key = percent_decode_str(key)
                        .decode_utf8()
                        .unwrap_or_else(|_| std::borrow::Cow::from(key));
                    let value = percent_decode_str(value)
                        .decode_utf8()
                        .unwrap_or_else(|_| std::borrow::Cow::from(value));
                    result.set(key.to_string(), value.to_string())?;
                }
            }
            Ok(result)
        })?;
        http_module.set("parse_query", parse_query_fn)?;

        // http.build_query(table) -> string
        let build_query_fn = lua.create_function(|_, params: LuaTable| {
            let mut pairs = Vec::new();
            for pair in params.pairs::<String, String>() {
                let (key, value) = pair?;
                pairs.push(format!(
                    "{}={}",
                    percent_encode(key.as_bytes(), NON_ALPHANUMERIC),
                    percent_encode(value.as_bytes(), NON_ALPHANUMERIC)
                ));
            }
            Ok(pairs.join("&"))
        })?;
        http_module.set("build_query", build_query_fn)?;

        // http.parse_cookies(cookie_header) -> table
        let parse_cookies_fn = lua.create_function(|lua, cookie_header: String| {
            let cookies = lua.create_table()?;
            for cookie in cookie_header.split(';') {
                let cookie = cookie.trim();
                if let Some((name, value)) = cookie.split_once('=') {
                    cookies.set(name.trim(), value.trim())?;
                }
            }
            Ok(cookies)
        })?;
        http_module.set("parse_cookies", parse_cookies_fn)?;

        // http.status_text(code) -> string
        let status_text_fn = lua.create_function(|_, code: u16| {
            Ok(match code {
                200 => "OK",
                201 => "Created",
                204 => "No Content",
                301 => "Moved Permanently",
                302 => "Found",
                304 => "Not Modified",
                400 => "Bad Request",
                401 => "Unauthorized",
                403 => "Forbidden",
                404 => "Not Found",
                405 => "Method Not Allowed",
                429 => "Too Many Requests",
                500 => "Internal Server Error",
                502 => "Bad Gateway",
                503 => "Service Unavailable",
                504 => "Gateway Timeout",
                _ => "Unknown",
            }
            .to_string())
        })?;
        http_module.set("status_text", status_text_fn)?;

        lua.globals().set("http", http_module)?;
        Ok(())
    }

    /// Load encoding module
    fn load_encoding(lua: &Lua) -> Result<()> {
        let encoding_module = lua.create_table()?;

        // encoding.base64_encode(data) -> string
        let base64_encode_fn = lua.create_function(|_, data: LuaString| {
            Ok(BASE64.encode(data.as_bytes()))
        })?;
        encoding_module.set("base64_encode", base64_encode_fn)?;

        // encoding.base64_decode(string) -> data
        let base64_decode_fn = lua.create_function(|lua, encoded: String| {
            BASE64
                .decode(encoded)
                .map(|bytes| lua.create_string(&bytes))
                .map_err(|e| LuaError::RuntimeError(format!("Base64 decode error: {}", e)))?
        })?;
        encoding_module.set("base64_decode", base64_decode_fn)?;

        // encoding.hex_encode(data) -> string
        let hex_encode_fn = lua.create_function(|_, data: LuaString| {
            Ok(hex::encode(data.as_bytes()))
        })?;
        encoding_module.set("hex_encode", hex_encode_fn)?;

        // encoding.hex_decode(string) -> data
        let hex_decode_fn = lua.create_function(|lua, encoded: String| {
            hex::decode(encoded)
                .map(|bytes| lua.create_string(&bytes))
                .map_err(|e| LuaError::RuntimeError(format!("Hex decode error: {}", e)))?
        })?;
        encoding_module.set("hex_decode", hex_decode_fn)?;

        // encoding.gzip_compress(data) -> compressed
        let gzip_compress_fn = lua.create_function(|lua, data: LuaString| {
            let mut encoder = GzEncoder::new(Vec::new(), Compression::default());
            encoder
                .write_all(data.as_bytes())
                .map_err(|e| LuaError::RuntimeError(format!("Gzip compress error: {}", e)))?;
            let compressed = encoder
                .finish()
                .map_err(|e| LuaError::RuntimeError(format!("Gzip compress error: {}", e)))?;
            lua.create_string(&compressed)
        })?;
        encoding_module.set("gzip_compress", gzip_compress_fn)?;

        // encoding.gzip_decompress(compressed) -> data
        let gzip_decompress_fn = lua.create_function(|lua, compressed: LuaString| {
            let mut decoder = GzDecoder::new(compressed.as_bytes());
            let mut decompressed = Vec::new();
            decoder
                .read_to_end(&mut decompressed)
                .map_err(|e| LuaError::RuntimeError(format!("Gzip decompress error: {}", e)))?;
            lua.create_string(&decompressed)
        })?;
        encoding_module.set("gzip_decompress", gzip_decompress_fn)?;

        lua.globals().set("encoding", encoding_module)?;
        Ok(())
    }

    /// Load string extensions
    fn load_string_ext(lua: &Lua) -> Result<()> {
        let string_ext = lua.create_table()?;

        // string_ext.split(string, separator) -> table
        let split_fn = lua.create_function(|lua, (text, sep): (String, String)| {
            let parts = lua.create_table()?;
            for (i, part) in text.split(&sep).enumerate() {
                parts.set(i + 1, part)?;
            }
            Ok(parts)
        })?;
        string_ext.set("split", split_fn)?;

        // string_ext.trim(string) -> string
        let trim_fn = lua.create_function(|_, text: String| Ok(text.trim().to_string()))?;
        string_ext.set("trim", trim_fn)?;

        // string_ext.starts_with(string, prefix) -> boolean
        let starts_with_fn =
            lua.create_function(|_, (text, prefix): (String, String)| Ok(text.starts_with(&prefix)))?;
        string_ext.set("starts_with", starts_with_fn)?;

        // string_ext.ends_with(string, suffix) -> boolean
        let ends_with_fn =
            lua.create_function(|_, (text, suffix): (String, String)| Ok(text.ends_with(&suffix)))?;
        string_ext.set("ends_with", ends_with_fn)?;

        // string_ext.contains(string, substring) -> boolean
        let contains_fn =
            lua.create_function(|_, (text, substr): (String, String)| Ok(text.contains(&substr)))?;
        string_ext.set("contains", contains_fn)?;

        // string_ext.replace(string, from, to) -> string
        let replace_fn = lua.create_function(|_, (text, from, to): (String, String, String)| {
            Ok(text.replace(&from, &to))
        })?;
        string_ext.set("replace", replace_fn)?;

        lua.globals().set("string_ext", string_ext)?;
        Ok(())
    }

    /// Load regex module
    fn load_regex(lua: &Lua) -> Result<()> {
        let regex_module = lua.create_table()?;

        // regex.match(pattern, text) -> boolean
        let match_fn = lua.create_function(|_, (pattern, text): (String, String)| {
            match Regex::new(&pattern) {
                Ok(re) => Ok(re.is_match(&text)),
                Err(e) => Err(LuaError::RuntimeError(format!("Regex error: {}", e))),
            }
        })?;
        regex_module.set("match", match_fn)?;

        // regex.find(pattern, text) -> string or nil
        let find_fn = lua.create_function(|_, (pattern, text): (String, String)| {
            match Regex::new(&pattern) {
                Ok(re) => Ok(re.find(&text).map(|m| m.as_str().to_string())),
                Err(e) => Err(LuaError::RuntimeError(format!("Regex error: {}", e))),
            }
        })?;
        regex_module.set("find", find_fn)?;

        // regex.find_all(pattern, text) -> table
        let find_all_fn = lua.create_function(|lua, (pattern, text): (String, String)| {
            match Regex::new(&pattern) {
                Ok(re) => {
                    let matches = lua.create_table()?;
                    for (i, mat) in re.find_iter(&text).enumerate() {
                        matches.set(i + 1, mat.as_str())?;
                    }
                    Ok(matches)
                }
                Err(e) => Err(LuaError::RuntimeError(format!("Regex error: {}", e))),
            }
        })?;
        regex_module.set("find_all", find_all_fn)?;

        // regex.replace(pattern, text, replacement) -> string
        let replace_fn =
            lua.create_function(|_, (pattern, text, replacement): (String, String, String)| {
                match Regex::new(&pattern) {
                    Ok(re) => Ok(re.replace_all(&text, replacement.as_str()).to_string()),
                    Err(e) => Err(LuaError::RuntimeError(format!("Regex error: {}", e))),
                }
            })?;
        regex_module.set("replace", replace_fn)?;

        lua.globals().set("regex", regex_module)?;
        Ok(())
    }

    /// Load time module
    fn load_time(lua: &Lua) -> Result<()> {
        let time_module = lua.create_table()?;

        // time.now() -> number (unix timestamp)
        let now_fn = lua.create_function(|_, ()| {
            Ok(Utc::now().timestamp() as f64)
        })?;
        time_module.set("now", now_fn)?;

        // time.now_ms() -> number (unix timestamp in milliseconds)
        let now_ms_fn = lua.create_function(|_, ()| {
            Ok(Utc::now().timestamp_millis() as f64)
        })?;
        time_module.set("now_ms", now_ms_fn)?;

        // time.format(timestamp, format) -> string
        let format_fn = lua.create_function(|_, (timestamp, format): (f64, Option<String>)| {
            let dt = DateTime::<Utc>::from_timestamp(timestamp as i64, 0)
                .ok_or_else(|| LuaError::RuntimeError("Invalid timestamp".to_string()))?;
            let format = format.as_deref().unwrap_or("%Y-%m-%d %H:%M:%S");
            Ok(dt.format(format).to_string())
        })?;
        time_module.set("format", format_fn)?;

        // time.parse(date_string, format) -> number
        let parse_fn = lua.create_function(|_, (date_str, format): (String, Option<String>)| {
            let format = format.as_deref().unwrap_or("%Y-%m-%d %H:%M:%S");
            DateTime::parse_from_str(&date_str, format)
                .map(|dt| dt.timestamp() as f64)
                .map_err(|e| LuaError::RuntimeError(format!("Date parse error: {}", e)))
        })?;
        time_module.set("parse", parse_fn)?;

        lua.globals().set("time", time_module)?;
        Ok(())
    }

    /// Load Sentinel-specific functions
    fn load_sentinel(lua: &Lua) -> Result<()> {
        let sentinel = lua.create_table()?;

        // sentinel.log(level, message)
        let log_fn = lua.create_function(|_, (level, message): (String, String)| {
            match level.to_lowercase().as_str() {
                "debug" => debug!("[Lua] {}", message),
                "info" => tracing::info!("[Lua] {}", message),
                "warn" => warn!("[Lua] {}", message),
                "error" => tracing::error!("[Lua] {}", message),
                _ => tracing::info!("[Lua] {}", message),
            }
            Ok(())
        })?;
        sentinel.set("log", log_fn)?;

        // sentinel.set_decision(decision)
        let set_decision_fn = lua.create_function(|lua, decision: String| {
            lua.globals().set("_decision", decision)?;
            Ok(())
        })?;
        sentinel.set("set_decision", set_decision_fn)?;

        // sentinel.add_metadata(key, value)
        let add_metadata_fn = lua.create_function(|lua, (key, value): (String, String)| {
            let metadata: LuaTable = lua.globals().get("_metadata").unwrap_or_else(|_| {
                let table = lua.create_table().unwrap();
                lua.globals().set("_metadata", table.clone()).unwrap();
                table
            });
            metadata.set(key, value)?;
            Ok(())
        })?;
        sentinel.set("add_metadata", add_metadata_fn)?;

        // sentinel.version
        sentinel.set("version", env!("CARGO_PKG_VERSION"))?;

        lua.globals().set("sentinel", sentinel)?;
        Ok(())
    }
}

/// Convert Lua value to JSON
fn lua_to_json(value: LuaValue) -> Result<JsonValue, LuaError> {
    match value {
        LuaNil => Ok(JsonValue::Null),
        LuaValue::Boolean(b) => Ok(JsonValue::Bool(b)),
        LuaValue::Integer(i) => Ok(JsonValue::Number(i.into())),
        LuaValue::Number(n) => {
            serde_json::Number::from_f64(n)
                .map(JsonValue::Number)
                .ok_or_else(|| LuaError::RuntimeError("Invalid JSON number".to_string()))
        }
        LuaValue::String(s) => Ok(JsonValue::String(s.to_str()?.to_string())),
        LuaValue::Table(t) => {
            // Check if it's an array (sequential integer keys starting from 1)
            let len = t.len()?;
            if len > 0 {
                let mut is_array = true;
                for i in 1..=len {
                    if t.get::<i32, LuaValue>(i as i32).is_err() {
                        is_array = false;
                        break;
                    }
                }

                if is_array {
                    let mut array = Vec::new();
                    for i in 1..=len {
                        let value = t.get::<i32, LuaValue>(i as i32)?;
                        array.push(lua_to_json(value)?);
                    }
                    return Ok(JsonValue::Array(array));
                }
            }

            // It's an object
            let mut object = serde_json::Map::new();
            for pair in t.pairs::<LuaValue, LuaValue>() {
                let (k, v) = pair?;
                let key = match k {
                    LuaValue::String(s) => s.to_str()?.to_string(),
                    LuaValue::Integer(i) => i.to_string(),
                    LuaValue::Number(n) => n.to_string(),
                    _ => continue,
                };
                object.insert(key, lua_to_json(v)?);
            }
            Ok(JsonValue::Object(object))
        }
        _ => Err(LuaError::RuntimeError(format!(
            "Cannot convert {:?} to JSON",
            value
        ))),
    }
}

/// Convert JSON value to Lua
fn json_to_lua(lua: &Lua, value: JsonValue) -> Result<LuaValue, LuaError> {
    match value {
        JsonValue::Null => Ok(LuaNil),
        JsonValue::Bool(b) => Ok(LuaValue::Boolean(b)),
        JsonValue::Number(n) => {
            if let Some(i) = n.as_i64() {
                Ok(LuaValue::Integer(i))
            } else if let Some(f) = n.as_f64() {
                Ok(LuaValue::Number(f))
            } else {
                Ok(LuaValue::Number(n.as_f64().unwrap_or(0.0)))
            }
        }
        JsonValue::String(s) => Ok(LuaValue::String(lua.create_string(&s)?)),
        JsonValue::Array(arr) => {
            let table = lua.create_table()?;
            for (i, v) in arr.into_iter().enumerate() {
                table.set(i + 1, json_to_lua(lua, v)?)?;
            }
            Ok(LuaValue::Table(table))
        }
        JsonValue::Object(obj) => {
            let table = lua.create_table()?;
            for (k, v) in obj {
                table.set(k, json_to_lua(lua, v)?)?;
            }
            Ok(LuaValue::Table(table))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_json_roundtrip() {
        let lua = unsafe { Lua::unsafe_new() };
        LuaStdLib::load(&lua).unwrap();

        let result = lua
            .load(
                r#"
            local data = {
                name = "test",
                value = 42,
                nested = {
                    array = {1, 2, 3},
                    flag = true
                }
            }
            local json_str = json.encode(data)
            local decoded = json.decode(json_str)
            return decoded.name == "test" and decoded.value == 42
        "#,
            )
            .eval::<bool>()
            .unwrap();

        assert!(result);
    }

    #[test]
    fn test_crypto_functions() {
        let lua = unsafe { Lua::unsafe_new() };
        LuaStdLib::load(&lua).unwrap();

        let sha256_result = lua
            .load(r#"return crypto.sha256("hello")"#)
            .eval::<String>()
            .unwrap();

        assert_eq!(
            sha256_result,
            "2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824"
        );

        let hmac_result = lua
            .load(r#"return crypto.hmac_sha256("key", "message")"#)
            .eval::<String>()
            .unwrap();

        assert!(!hmac_result.is_empty());
    }

    #[test]
    fn test_http_utilities() {
        let lua = unsafe { Lua::unsafe_new() };
        LuaStdLib::load(&lua).unwrap();

        let encoded = lua
            .load(r#"return http.url_encode("hello world")"#)
            .eval::<String>()
            .unwrap();
        assert_eq!(encoded, "hello%20world");

        let decoded = lua
            .load(r#"return http.url_decode("hello%20world")"#)
            .eval::<String>()
            .unwrap();
        assert_eq!(decoded, "hello world");

        let query_parsed = lua
            .load(
                r#"
            local params = http.parse_query("foo=bar&baz=qux")
            return params.foo == "bar" and params.baz == "qux"
        "#,
            )
            .eval::<bool>()
            .unwrap();
        assert!(query_parsed);
    }

    #[test]
    fn test_string_extensions() {
        let lua = unsafe { Lua::unsafe_new() };
        LuaStdLib::load(&lua).unwrap();

        let split_result = lua
            .load(
                r#"
            local parts = string_ext.split("a,b,c", ",")
            return #parts == 3 and parts[1] == "a" and parts[2] == "b" and parts[3] == "c"
        "#,
            )
            .eval::<bool>()
            .unwrap();
        assert!(split_result);

        let trim_result = lua
            .load(r#"return string_ext.trim("  hello  ")"#)
            .eval::<String>()
            .unwrap();
        assert_eq!(trim_result, "hello");
    }

    #[test]
    fn test_base64_encoding() {
        let lua = unsafe { Lua::unsafe_new() };
        LuaStdLib::load(&lua).unwrap();

        let encoded = lua
            .load(r#"return encoding.base64_encode("hello")"#)
            .eval::<String>()
            .unwrap();
        assert_eq!(encoded, "aGVsbG8=");

        let decoded = lua
            .load(r#"return encoding.base64_decode("aGVsbG8=")"#)
            .eval::<String>()
            .unwrap();
        assert_eq!(decoded, "hello");
    }

    #[test]
    fn test_regex_functions() {
        let lua = unsafe { Lua::unsafe_new() };
        LuaStdLib::load(&lua).unwrap();

        let match_result = lua
            .load(r#"return regex.match("^hello", "hello world")"#)
            .eval::<bool>()
            .unwrap();
        assert!(match_result);

        let find_result = lua
            .load(r#"return regex.find("\\d+", "
