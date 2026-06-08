use anyhow::Result;
use zentinel_common::CircuitBreakerConfig;

use crate::kdl::helpers::{extract_u32_with_limits, extract_u64_with_limits};

/// Parse circuit breaker configuration
pub fn parse_circuit_breaker_faildefault(node: &kdl::KdlNode) -> Result<CircuitBreakerConfig> {
    let default_config = CircuitBreakerConfig::default();

    fn cb_config_map(
        mut cfg: CircuitBreakerConfig,
        node: &kdl::KdlNode,
    ) -> Result<CircuitBreakerConfig> {
        match node.name().to_string().as_str() {
            "failure-threshold" => {
                cfg.failure_threshold = extract_u32_with_limits(node)?;
            }
            "success-threshold" => {
                cfg.success_threshold = extract_u32_with_limits(node)?;
            }
            "timeout-seconds" => {
                cfg.timeout_seconds = extract_u64_with_limits(node)?;
            }
            "half-open-max-requests" => {
                cfg.half_open_max_requests = extract_u32_with_limits(node)?;
            }
            d => {
                return Err(anyhow::anyhow!("Got unknown key {}", d));
            }
        }

        Ok(cfg)
    }

    node.iter_children().try_fold(default_config, cb_config_map)
}

#[cfg(test)]
mod tests {
    use crate::kdl::circuitbreaker_helper::parse_circuit_breaker_faildefault;
    use zentinel_common::CircuitBreakerConfig;

    /// circuit-breaker stanza present, all values normally set, use those values
    #[test]
    fn test_parse_circuit_breaker_normal() {
        let kdl = r#"
            circuit-breaker {
                failure-threshold 1
                success-threshold 2
                timeout-seconds 4
                half-open-max-requests 8
            }
        "#;

        let doc: kdl::KdlDocument = kdl.parse().unwrap();
        let cb_node = doc.get("circuit-breaker").unwrap();

        let cbconfig = parse_circuit_breaker_faildefault(cb_node).unwrap();

        assert_eq!(cbconfig.failure_threshold, 1);
        assert_eq!(cbconfig.success_threshold, 2);
        assert_eq!(cbconfig.timeout_seconds, 4);
        assert_eq!(cbconfig.half_open_max_requests, 8);
    }

    /// circuit-breaker stanza present, one key unrecognized, expect to Err and panic out
    #[test]
    fn test_parse_circuit_breaker_badkey() {
        let kdl = r#"
            circuit-breaker {
                failure-threshold 1
                success-threshold 2
                timeout-sekonds 4
                half-open-max-requests 8
            }
        "#;

        let doc: kdl::KdlDocument = kdl.parse().unwrap();
        let cb_node = doc.get("circuit-breaker").unwrap();

        let cbconfig = parse_circuit_breaker_faildefault(cb_node);
        let err_msg = cbconfig.unwrap_err();

        assert_eq!(format!("{}", err_msg), "Got unknown key timeout-sekonds");
    }

    /// circuit-breaker stanza present, new key unrecognized, expect to Err and panic out
    #[test]
    fn test_parse_circuit_breaker_badnewkey() {
        let kdl = r#"
            circuit-breaker {
                failure-threshold 1
                success-threshold 2
                timeout-seconds 4
                half-open-max-requests 8
                reticulate 24
            }
        "#;

        let doc: kdl::KdlDocument = kdl.parse().unwrap();
        let cb_node = doc.get("circuit-breaker").unwrap();

        let cbconfig = parse_circuit_breaker_faildefault(cb_node);
        let err_msg = cbconfig.unwrap_err();

        assert_eq!(format!("{}", err_msg), "Got unknown key reticulate");
    }

    /// circuit-breaker stanza present, one value unrecognized, expect to Err and panic out
    #[test]
    fn test_parse_circuit_breaker_badval() {
        let kdl = r#"
            circuit-breaker {
                failure-threshold 1
                success-threshold 2
                timeout-seconds 4
                half-open-max-requests 'aaa'
            }
        "#;

        let doc: kdl::KdlDocument = kdl.parse().unwrap();
        let cb_node = doc.get("circuit-breaker").unwrap();

        let cbconfig = parse_circuit_breaker_faildefault(cb_node);
        let err_msg = cbconfig.unwrap_err();

        assert_eq!(
            format!("{}", err_msg),
            "Tried to convert value in half-open-max-requests to u32, but failed"
        );
    }

    /// circuit-breaker stanza present, one value out-of-bounds(0), expect to Err and crash
    #[test]
    fn test_parse_circuit_breaker_bounds_u32_check() {
        let kdl = r#"
            circuit-breaker {
                failure-threshold 1
                success-threshold 0
                timeout-seconds 4
                half-open-max-requests 8
            }
        "#;

        let doc: kdl::KdlDocument = kdl.parse().unwrap();
        let cb_node = doc.get("circuit-breaker").unwrap();

        let cbconfig = parse_circuit_breaker_faildefault(cb_node);
        let err_msg = cbconfig.unwrap_err();

        assert_eq!(
            format!("{}", err_msg),
            "Implausible value for success-threshold"
        );
    }

    /// circuit-breaker stanza present, one value overflows u32, expect to Err from TryFromIntError
    #[test]
    fn test_parse_circuit_breaker_overflow_u32_check() {
        let kdl = r#"
            circuit-breaker {
                failure-threshold 1
                success-threshold 4294967296
                timeout-seconds 4
                half-open-max-requests 8
            }
        "#;

        let doc: kdl::KdlDocument = kdl.parse().unwrap();
        let cb_node = doc.get("circuit-breaker").unwrap();

        let cbconfig = parse_circuit_breaker_faildefault(cb_node);
        let err_msg = cbconfig.unwrap_err();

        assert_eq!(
            format!("{}", err_msg),
            "out of range integral type conversion attempted"
        );
    }

    /// circuit-breaker stanza present, one value parse-error (negative), expect to Err from TryFromIntError
    #[test]
    fn test_parse_circuit_breaker_parseerr_u32_check() {
        let kdl = r#"
            circuit-breaker {
                failure-threshold 1
                success-threshold -42
                timeout-seconds 4
                half-open-max-requests 8
            }
        "#;

        let doc: kdl::KdlDocument = kdl.parse().unwrap();
        let cb_node = doc.get("circuit-breaker").unwrap();

        let cbconfig = parse_circuit_breaker_faildefault(cb_node);
        let err_msg = cbconfig.unwrap_err();

        assert_eq!(
            format!("{}", err_msg),
            "out of range integral type conversion attempted"
        );
    }

    /// circuit-breaker stanza present, one value out-of-bounds(0), expect to Err and crash
    #[test]
    fn test_parse_circuit_breaker_bounds_u64_check() {
        let kdl = r#"
            circuit-breaker {
                failure-threshold 1
                success-threshold 2
                timeout-seconds 0
                half-open-max-requests 8
            }
        "#;

        let doc: kdl::KdlDocument = kdl.parse().unwrap();
        let cb_node = doc.get("circuit-breaker").unwrap();

        let cbconfig = parse_circuit_breaker_faildefault(cb_node);
        let err_msg = cbconfig.unwrap_err();

        assert_eq!(
            format!("{}", err_msg),
            "Implausible value for timeout-seconds"
        );
    }

    /// circuit-breaker stanza present, one value parse-error (negative), expect to Err from TryFromIntError
    #[test]
    fn test_parse_circuit_breaker_parseerr_u64_check() {
        let kdl = r#"
            circuit-breaker {
                failure-threshold 1
                success-threshold 2
                timeout-seconds -42
                half-open-max-requests 8
            }
        "#;

        let doc: kdl::KdlDocument = kdl.parse().unwrap();
        let cb_node = doc.get("circuit-breaker").unwrap();

        let cbconfig = parse_circuit_breaker_faildefault(cb_node);
        let err_msg = cbconfig.unwrap_err();

        assert_eq!(
            format!("{}", err_msg),
            "out of range integral type conversion attempted"
        );
    }

    /// circuit-breaker stanza present, all values missing, defaults should be used
    #[test]
    fn test_parse_circuit_breaker_fields_missing() {
        let kdl = r#"
            circuit-breaker {
            } 
        "#;

        let doc: kdl::KdlDocument = kdl.parse().unwrap();
        let cb_node = doc.get("circuit-breaker").unwrap();

        let cbconfig = parse_circuit_breaker_faildefault(cb_node).unwrap();

        let cb_default = CircuitBreakerConfig::default();

        assert_eq!(cbconfig.failure_threshold, cb_default.failure_threshold);
        assert_eq!(cbconfig.success_threshold, cb_default.success_threshold);
        assert_eq!(cbconfig.timeout_seconds, cb_default.timeout_seconds);
        assert_eq!(
            cbconfig.half_open_max_requests,
            cb_default.half_open_max_requests
        );
    }

    /// circuit-breaker stanza present, some values missing, defaults should be used for missing
    #[test]
    fn test_parse_circuit_breaker_some_fields_missing() {
        let kdl = r#"
            circuit-breaker {
                timeout-seconds 4
            }
        "#;

        let doc: kdl::KdlDocument = kdl.parse().unwrap();
        let cb_node = doc.get("circuit-breaker").unwrap();

        let cbconfig = parse_circuit_breaker_faildefault(cb_node).unwrap();

        let cb_default = CircuitBreakerConfig::default();

        assert_eq!(cbconfig.failure_threshold, cb_default.failure_threshold);
        assert_eq!(cbconfig.success_threshold, cb_default.success_threshold);
        assert_eq!(cbconfig.timeout_seconds, 4);
        assert_eq!(
            cbconfig.half_open_max_requests,
            cb_default.half_open_max_requests
        );
    }
}
