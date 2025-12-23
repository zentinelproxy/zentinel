//! API schema validation module for Sentinel proxy
//!
//! This module provides JSON Schema validation for API routes,
//! supporting both request and response validation with OpenAPI integration.

use anyhow::{Context, Result};
use bytes::Bytes;
use http::{Request, Response, StatusCode};
use http_body_util::{BodyExt, Full};
use jsonschema::{Draft, JSONSchema, ValidationError};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use std::collections::HashMap;
use std::path::Path;
use std::sync::Arc;
use tracing::{debug, error, info, warn};

use sentinel_config::ApiSchemaConfig;

/// API schema validator
pub struct SchemaValidator {
    /// Configuration for schema validation
    config: Arc<ApiSchemaConfig>,
    /// Compiled request schema
    request_schema: Option<Arc<JSONSchema>>,
    /// Compiled response schema
    response_schema: Option<Arc<JSONSchema>>,
    /// OpenAPI specification (if loaded)
    openapi_spec: Option<OpenApiSpec>,
}

/// OpenAPI specification
#[derive(Debug, Clone, Deserialize)]
struct OpenApiSpec {
    openapi: String,
    paths: HashMap<String, PathItem>,
    components: Option<Components>,
}

/// OpenAPI path item
#[derive(Debug, Clone, Deserialize)]
struct PathItem {
    #[serde(default)]
    get: Option<Operation>,
    #[serde(default)]
    post: Option<Operation>,
    #[serde(default)]
    put: Option<Operation>,
    #[serde(default)]
    delete: Option<Operation>,
    #[serde(default)]
    patch: Option<Operation>,
}

/// OpenAPI operation
#[derive(Debug, Clone, Deserialize)]
struct Operation {
    #[serde(rename = "operationId")]
    operation_id: Option<String>,
    #[serde(rename = "requestBody")]
    request_body: Option<RequestBody>,
    responses: HashMap<String, ApiResponse>,
}

/// OpenAPI request body
#[derive(Debug, Clone, Deserialize)]
struct RequestBody {
    required: Option<bool>,
    content: HashMap<String, MediaType>,
}

/// OpenAPI response
#[derive(Debug, Clone, Deserialize)]
struct ApiResponse {
    description: String,
    content: Option<HashMap<String, MediaType>>,
}

/// OpenAPI media type
#[derive(Debug, Clone, Deserialize)]
struct MediaType {
    schema: Option<Value>,
}

/// OpenAPI components
#[derive(Debug, Clone, Deserialize)]
struct Components {
    schemas: Option<HashMap<String, Value>>,
}

/// Validation error response
#[derive(Debug, Serialize)]
pub struct ValidationErrorResponse {
    pub error: String,
    pub status: u16,
    pub validation_errors: Vec<ValidationErrorDetail>,
    pub request_id: String,
}

/// Individual validation error detail
#[derive(Debug, Serialize)]
pub struct ValidationErrorDetail {
    pub field: String,
    pub message: String,
    pub value: Option<Value>,
}

impl SchemaValidator {
    /// Create a new schema validator
    pub fn new(config: ApiSchemaConfig) -> Result<Self> {
        let mut validator = Self {
            config: Arc::new(config.clone()),
            request_schema: None,
            response_schema: None,
            openapi_spec: None,
        };

        // Load OpenAPI specification if provided
        if let Some(ref schema_file) = config.schema_file {
            validator.load_openapi_spec(schema_file)?;
        }

        // Compile request schema if provided
        if let Some(ref schema) = config.request_schema {
            validator.request_schema = Some(Arc::new(Self::compile_schema(schema)?));
        }

        // Compile response schema if provided
        if let Some(ref schema) = config.response_schema {
            validator.response_schema = Some(Arc::new(Self::compile_schema(schema)?));
        }

        Ok(validator)
    }

    /// Load OpenAPI specification from file
    fn load_openapi_spec(&mut self, path: &Path) -> Result<()> {
        let content = std::fs::read_to_string(path)
            .with_context(|| format!("Failed to read OpenAPI spec: {:?}", path))?;

        let spec: OpenApiSpec = if path
            .extension()
            .map_or(false, |e| e == "yaml" || e == "yml")
        {
            serde_yaml::from_str(&content)?
        } else {
            serde_json::from_str(&content)?
        };

        info!("Loaded OpenAPI specification from {:?}", path);
        self.openapi_spec = Some(spec);
        Ok(())
    }

    /// Compile a JSON schema
    fn compile_schema(schema: &Value) -> Result<JSONSchema> {
        JSONSchema::options()
            .with_draft(Draft::Draft7)
            .compile(schema)
            .map_err(|e| anyhow::anyhow!("Failed to compile schema: {}", e))
    }

    /// Validate a request
    pub async fn validate_request<B>(
        &self,
        request: &Request<B>,
        body: &[u8],
        path: &str,
        request_id: &str,
    ) -> Result<()> {
        if !self.config.validate_requests {
            return Ok(());
        }

        // Parse JSON body
        let json_body: Value = if body.is_empty() {
            json!(null)
        } else {
            serde_json::from_slice(body).map_err(|e| self.create_parsing_error(e, request_id))?
        };

        // Get the appropriate schema
        let schema = if let Some(ref request_schema) = self.request_schema {
            request_schema.clone()
        } else if let Some(ref spec) = self.openapi_spec {
            // Try to find schema from OpenAPI spec
            match self.get_request_schema_from_spec(spec, path, request.method().as_str()) {
                Some(s) => Arc::new(Self::compile_schema(&s)?),
                None => {
                    debug!("No schema found for {} {}", request.method(), path);
                    return Ok(());
                }
            }
        } else {
            // No schema configured
            return Ok(());
        };

        // Validate against schema
        self.validate_against_schema(&schema, &json_body, request_id)?;

        Ok(())
    }

    /// Validate a response
    pub async fn validate_response(
        &self,
        status: StatusCode,
        body: &[u8],
        path: &str,
        method: &str,
        request_id: &str,
    ) -> Result<()> {
        if !self.config.validate_responses {
            return Ok(());
        }

        // Parse JSON body
        let json_body: Value = if body.is_empty() {
            json!(null)
        } else {
            serde_json::from_slice(body).map_err(|e| self.create_parsing_error(e, request_id))?
        };

        // Get the appropriate schema
        let schema = if let Some(ref response_schema) = self.response_schema {
            response_schema.clone()
        } else if let Some(ref spec) = self.openapi_spec {
            // Try to find schema from OpenAPI spec
            match self.get_response_schema_from_spec(spec, path, method, status.as_u16()) {
                Some(s) => Arc::new(Self::compile_schema(&s)?),
                None => {
                    debug!(
                        "No schema found for {} {} response {}",
                        method, path, status
                    );
                    return Ok(());
                }
            }
        } else {
            // No schema configured
            return Ok(());
        };

        // Validate against schema
        self.validate_against_schema(&schema, &json_body, request_id)?;

        Ok(())
    }

    /// Validate JSON against a schema
    fn validate_against_schema(
        &self,
        schema: &JSONSchema,
        instance: &Value,
        request_id: &str,
    ) -> Result<()> {
        let result = schema.validate(instance);

        if let Err(errors) = result {
            let validation_errors: Vec<ValidationErrorDetail> = errors
                .map(|error| self.format_validation_error(error, instance))
                .collect();

            if !validation_errors.is_empty() {
                return Err(self.create_validation_error(validation_errors, request_id));
            }
        }

        // Additional strict mode checks
        if self.config.strict_mode {
            self.strict_mode_checks(schema, instance, request_id)?;
        }

        Ok(())
    }

    /// Format a validation error
    fn format_validation_error(
        &self,
        error: ValidationError,
        instance: &Value,
    ) -> ValidationErrorDetail {
        let field = error.instance_path.to_string();
        let field = if field.is_empty() {
            "$".to_string()
        } else {
            field
        };

        let value = error
            .instance_path
            .iter()
            .fold(Some(instance), |acc, segment| {
                acc.and_then(|v| match segment {
                    jsonschema::paths::PathChunk::Property(prop) => v.get(prop.as_ref()),
                    jsonschema::paths::PathChunk::Index(idx) => v.get(idx),
                    _ => None,
                })
            })
            .cloned();

        ValidationErrorDetail {
            field,
            message: error.to_string(),
            value,
        }
    }

    /// Perform strict mode checks
    fn strict_mode_checks(
        &self,
        _schema: &JSONSchema,
        instance: &Value,
        _request_id: &str,
    ) -> Result<()> {
        // Check for null values
        if self.has_null_values(instance) {
            warn!("Strict mode: Found null values in JSON");
        }

        // Check for empty strings
        if self.has_empty_strings(instance) {
            warn!("Strict mode: Found empty strings in JSON");
        }

        Ok(())
    }

    /// Check if JSON contains null values
    fn has_null_values(&self, value: &Value) -> bool {
        match value {
            Value::Null => true,
            Value::Array(arr) => arr.iter().any(|v| self.has_null_values(v)),
            Value::Object(obj) => obj.values().any(|v| self.has_null_values(v)),
            _ => false,
        }
    }

    /// Check if JSON contains empty strings
    fn has_empty_strings(&self, value: &Value) -> bool {
        match value {
            Value::String(s) if s.is_empty() => true,
            Value::Array(arr) => arr.iter().any(|v| self.has_empty_strings(v)),
            Value::Object(obj) => obj.values().any(|v| self.has_empty_strings(v)),
            _ => false,
        }
    }

    /// Get request schema from OpenAPI spec
    fn get_request_schema_from_spec(
        &self,
        spec: &OpenApiSpec,
        path: &str,
        method: &str,
    ) -> Option<Value> {
        let path_item = spec.paths.get(path)?;
        let operation = match method.to_lowercase().as_str() {
            "get" => path_item.get.as_ref(),
            "post" => path_item.post.as_ref(),
            "put" => path_item.put.as_ref(),
            "delete" => path_item.delete.as_ref(),
            "patch" => path_item.patch.as_ref(),
            _ => None,
        }?;

        let request_body = operation.request_body.as_ref()?;
        let media_type = request_body.content.get("application/json")?;
        media_type.schema.clone()
    }

    /// Get response schema from OpenAPI spec
    fn get_response_schema_from_spec(
        &self,
        spec: &OpenApiSpec,
        path: &str,
        method: &str,
        status: u16,
    ) -> Option<Value> {
        let path_item = spec.paths.get(path)?;
        let operation = match method.to_lowercase().as_str() {
            "get" => path_item.get.as_ref(),
            "post" => path_item.post.as_ref(),
            "put" => path_item.put.as_ref(),
            "delete" => path_item.delete.as_ref(),
            "patch" => path_item.patch.as_ref(),
            _ => None,
        }?;

        // Try exact status code first, then default
        let response = operation
            .responses
            .get(&status.to_string())
            .or_else(|| operation.responses.get("default"))?;

        let content = response.content.as_ref()?;
        let media_type = content.get("application/json")?;
        media_type.schema.clone()
    }

    /// Create a parsing error response
    fn create_parsing_error(&self, error: serde_json::Error, request_id: &str) -> anyhow::Error {
        let error_response = ValidationErrorResponse {
            error: "Invalid JSON".to_string(),
            status: 400,
            validation_errors: vec![ValidationErrorDetail {
                field: "$".to_string(),
                message: error.to_string(),
                value: None,
            }],
            request_id: request_id.to_string(),
        };

        anyhow::anyhow!(serde_json::to_string(&error_response)
            .unwrap_or_else(|_| { format!("JSON parsing error: {}", error) }))
    }

    /// Create a validation error response
    fn create_validation_error(
        &self,
        errors: Vec<ValidationErrorDetail>,
        request_id: &str,
    ) -> anyhow::Error {
        let error_response = ValidationErrorResponse {
            error: "Validation failed".to_string(),
            status: 400,
            validation_errors: errors,
            request_id: request_id.to_string(),
        };

        anyhow::anyhow!(serde_json::to_string(&error_response)
            .unwrap_or_else(|_| { "Validation failed".to_string() }))
    }

    /// Generate validation error response
    pub fn generate_error_response(
        &self,
        errors: Vec<ValidationErrorDetail>,
        request_id: &str,
    ) -> Response<Full<Bytes>> {
        let error_response = ValidationErrorResponse {
            error: "Validation failed".to_string(),
            status: 400,
            validation_errors: errors,
            request_id: request_id.to_string(),
        };

        let body = serde_json::to_vec(&error_response)
            .unwrap_or_else(|_| br#"{"error":"Validation failed","status":400}"#.to_vec());

        Response::builder()
            .status(StatusCode::BAD_REQUEST)
            .header("Content-Type", "application/json")
            .header("X-Request-Id", request_id)
            .body(Full::new(Bytes::from(body)))
            .unwrap_or_else(|_| {
                Response::builder()
                    .status(StatusCode::INTERNAL_SERVER_ERROR)
                    .body(Full::new(Bytes::new()))
                    .unwrap()
            })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn test_schema_validation() {
        let schema = json!({
            "type": "object",
            "properties": {
                "name": {
                    "type": "string",
                    "minLength": 1
                },
                "age": {
                    "type": "integer",
                    "minimum": 0
                }
            },
            "required": ["name"]
        });

        let config = ApiSchemaConfig {
            schema_file: None,
            request_schema: Some(schema),
            response_schema: None,
            validate_requests: true,
            validate_responses: false,
            strict_mode: false,
        };

        let validator = SchemaValidator::new(config).unwrap();

        // Valid JSON
        let valid_json = json!({
            "name": "John",
            "age": 30
        });

        let schema = validator.request_schema.as_ref().unwrap();
        let result = validator.validate_against_schema(schema, &valid_json, "test-123");
        assert!(result.is_ok());

        // Invalid JSON (missing required field)
        let invalid_json = json!({
            "age": 30
        });

        let result = validator.validate_against_schema(schema, &invalid_json, "test-124");
        assert!(result.is_err());

        // Invalid JSON (wrong type)
        let invalid_json = json!({
            "name": 123,
            "age": "thirty"
        });

        let result = validator.validate_against_schema(schema, &invalid_json, "test-125");
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn test_request_validation() {
        let schema = json!({
            "type": "object",
            "properties": {
                "email": {
                    "type": "string",
                    "format": "email"
                },
                "password": {
                    "type": "string",
                    "minLength": 8
                }
            },
            "required": ["email", "password"]
        });

        let config = ApiSchemaConfig {
            schema_file: None,
            request_schema: Some(schema),
            response_schema: None,
            validate_requests: true,
            validate_responses: false,
            strict_mode: false,
        };

        let validator = SchemaValidator::new(config).unwrap();

        let request = Request::post("/login")
            .header("Content-Type", "application/json")
            .body(())
            .unwrap();

        // Valid request body
        let valid_body = json!({
            "email": "user@example.com",
            "password": "securepassword123"
        });
        let body_bytes = serde_json::to_vec(&valid_body).unwrap();

        let result = validator
            .validate_request(&request, &body_bytes, "/login", "req-001")
            .await;
        assert!(result.is_ok());

        // Invalid request body
        let invalid_body = json!({
            "email": "not-an-email",
            "password": "short"
        });
        let body_bytes = serde_json::to_vec(&invalid_body).unwrap();

        let result = validator
            .validate_request(&request, &body_bytes, "/login", "req-002")
            .await;
        assert!(result.is_err());
    }
}
