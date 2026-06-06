use anyhow::Result;
use zentinel_common::CircuitBreakerConfig;

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

fn extract_u32_with_limits(node: &kdl::KdlNode) -> Result<u32> {
    let first_value = match node.entries().first() {
        Some(v) => v,
        None => {
            return Err(anyhow::anyhow!(
                "Tried to parse u32 for key {} but did not find a value",
                node.name()
            ))
        }
    };
    let u32_val = match first_value.value().as_integer() {
        Some(v) => u32::try_from(v).map_err(anyhow::Error::msg)?,
        None => {
            return Err(anyhow::anyhow!(
                "Tried to convert value in {} to u32, but failed",
                node.name()
            ))
        }
    };

    if u32_val == 0 {
        return Err(anyhow::anyhow!("Implausible value for {}", node.name()));
    }

    Ok(u32_val)
}

fn extract_u64_with_limits(node: &kdl::KdlNode) -> Result<u64> {
    let first_value = match node.entries().first() {
        Some(v) => v,
        None => {
            return Err(anyhow::anyhow!(
                "Tried to parse u64 for key {} but did not find a value",
                node.name()
            ))
        }
    };
    let u64_val = match first_value.value().as_integer() {
        Some(v) => u64::try_from(v).map_err(anyhow::Error::msg)?,
        None => {
            return Err(anyhow::anyhow!(
                "Tried to convert value in {} to u64, but failed",
                node.name()
            ))
        }
    };

    if u64_val == 0 {
        return Err(anyhow::anyhow!("Implausible value for {}", node.name()));
    }

    Ok(u64_val)
}
