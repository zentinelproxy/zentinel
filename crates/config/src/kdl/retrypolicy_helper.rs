use anyhow::{Context, Result};
use tracing::warn;
use zentinel_common::types::RetryPolicy;

pub fn parse_retry_policy(node: &kdl::KdlNode) -> Result<RetryPolicy> {
    let default_config = RetryPolicy::default();

    fn rp_config_map(mut cfg: RetryPolicy, node: &kdl::KdlNode) -> Result<RetryPolicy> {
        match node.name().to_string().as_str() {
            "max-attempts" => {
                cfg.max_attempts = extract_u32_with_limits(node)?;
            }
            "timeout-ms" => {
                cfg.timeout_ms = extract_u64_with_limits(node)?;
                warn!("timeout-ms setting is parsed, but not implemented");
            }
            "backoff-base-ms" => {
                cfg.backoff_base_ms = extract_u64_with_limits(node)?;
                warn!("backoff-base-ms setting is parsed, but not implemented");
            }
            "backoff-max-ms" => {
                cfg.backoff_max_ms = extract_u64_with_limits(node)?;
                warn!("backoff-max-ms setting is parsed, but not implemented");
            }
            "retryable-status-codes" => {
                cfg.retryable_status_codes = extract_vec_u16_statuscodes(node)?;
                warn!("retryable-status-codes setting is parsed, but not implemented");
            }
            d => {
                return Err(anyhow::anyhow!("Got unknown key {}", d));
            }
        }

        Ok(cfg)
    }

    node.iter_children().try_fold(default_config, rp_config_map)
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

fn extract_vec_u16_statuscodes(node: &kdl::KdlNode) -> Result<Vec<u16>> {
    let statuscode_range = 100..=599;
    let mut statuscodes: Vec<u16> = vec![];
    for code in node.entries() {
        let qcode = u16::try_from(
            code.value()
                .as_integer()
                .context("Tried to convert statuscode to u16 but failed")?,
        )?;

        if statuscode_range.contains(&qcode) {
            statuscodes.push(qcode);
        } else {
            return Err(anyhow::anyhow!("Status code {} is not a valid code", qcode));
        }
    }
    Ok(statuscodes)
}

#[cfg(test)]
mod tests {
    use zentinel_common::types::RetryPolicy;

    use crate::kdl::retrypolicy_helper::parse_retry_policy;

    /// retry-policy stanza present, all values normally set, use those values
    #[test]
    fn test_parse_retry_policy_normal() {
        let kdl = r#"
            retry-policy {
                max-attempts 10
                timeout-ms 20
                backoff-base-ms 30
                backoff-max-ms 40
                retryable-status-codes 550 551 552
            }
        "#;

        let doc: kdl::KdlDocument = kdl.parse().unwrap();
        let rp_node = doc.get("retry-policy").unwrap();

        let rp = parse_retry_policy(rp_node).unwrap();

        assert_eq!(rp.max_attempts, 10);
        assert_eq!(rp.timeout_ms, 20);
        assert_eq!(rp.backoff_base_ms, 30);
        assert_eq!(rp.backoff_max_ms, 40);
        assert_eq!(rp.retryable_status_codes, vec![550, 551, 552]);
    }

    /// retry-policy stanza present, one key unrecognized, expect to Err and panic out
    #[test]
    fn test_parse_retry_policy_badkey() {
        let kdl = r#"
            retry-policy {
                max-attempt 3
                timeout-ms 30000
                backoff-base-ms 100
                backoff-max-ms 10000
                retryable-status-codes 502 503 504
            }
        "#;

        let doc: kdl::KdlDocument = kdl.parse().unwrap();
        let rp_node = doc.get("retry-policy").unwrap();

        let rp = parse_retry_policy(rp_node);
        let err_msg = rp.unwrap_err();
        assert_eq!(format!("{}", err_msg), "Got unknown key max-attempt");
    }

    /// retry-policy stanza present, new key unrecognized, expect to Err and panic out
    #[test]
    fn test_parse_retry_policy_badnewkey() {
        let kdl = r#"
            retry-policy {
                max-attempts 3
                timeout-ms 30000
                backoff-base-ms 100
                backoff-max-ms 10000
                retryable-status-codes 502 503 504
                frob 2
            }
        "#;

        let doc: kdl::KdlDocument = kdl.parse().unwrap();
        let rp_node = doc.get("retry-policy").unwrap();

        let rp = parse_retry_policy(rp_node);
        let err_msg = rp.unwrap_err();
        assert_eq!(format!("{}", err_msg), "Got unknown key frob");
    }

    /// retry-policy stanza present, one value unrecognized, expect to Err and panic out
    #[test]
    fn test_parse_retry_policy_badval() {
        let kdl = r#"
            retry-policy {
                max-attempts 3
                timeout-ms 30000
                backoff-base-ms 100
                backoff-max-ms "one thousand"
                retryable-status-codes 502 503 504
            }
        "#;

        let doc: kdl::KdlDocument = kdl.parse().unwrap();
        let rp_node = doc.get("retry-policy").unwrap();

        let rp = parse_retry_policy(rp_node);
        let err_msg = rp.unwrap_err();
        assert_eq!(
            format!("{}", err_msg),
            "Tried to convert value in backoff-max-ms to u64, but failed"
        );
    }

    /// retry-policy stanza present, one value out-of-bounds(0), expect to Err and crash
    #[test]
    fn test_parse_retry_policy_u32_check() {
        let kdl = r#"
            retry-policy {
                max-attempts 0
                timeout-ms 30000
                backoff-base-ms 100
                backoff-max-ms 10000
                retryable-status-codes 502 503 504
            }
        "#;

        let doc: kdl::KdlDocument = kdl.parse().unwrap();
        let rp_node = doc.get("retry-policy").unwrap();

        let rp = parse_retry_policy(rp_node);
        let err_msg = rp.unwrap_err();
        assert_eq!(format!("{}", err_msg), "Implausible value for max-attempts");
    }

    /// retry-policy stanza present, one value overflows u32, expect to Err from TryFromIntError
    #[test]
    fn test_parse_retry_policy_overflow_u32_check() {
        let kdl = r#"
            retry-policy {
                max-attempts 4294967296
                timeout-ms 30000
                backoff-base-ms 100
                backoff-max-ms 10000
                retryable-status-codes 502 503 504
            }
        "#;

        let doc: kdl::KdlDocument = kdl.parse().unwrap();
        let rp_node = doc.get("retry-policy").unwrap();

        let rp = parse_retry_policy(rp_node);
        let err_msg = rp.unwrap_err();
        assert_eq!(
            format!("{}", err_msg),
            "out of range integral type conversion attempted"
        );
    }

    /// retry-policy stanza present, one value parse-error (negative), expect to Err from TryFromIntError
    #[test]
    fn test_parse_retry_policy_parseerr_u32_check() {
        let kdl = r#"
            retry-policy {
                max-attempts -4
                timeout-ms 30000
                backoff-base-ms 100
                backoff-max-ms 10000
                retryable-status-codes 502 503 504
            }
        "#;

        let doc: kdl::KdlDocument = kdl.parse().unwrap();
        let rp_node = doc.get("retry-policy").unwrap();

        let rp = parse_retry_policy(rp_node);
        let err_msg = rp.unwrap_err();
        assert_eq!(
            format!("{}", err_msg),
            "out of range integral type conversion attempted"
        );
    }

    /// retry-policy stanza present, one value out-of-bounds(0), expect to Err and crash
    #[test]
    fn test_parse_retry_policy_u64_check() {
        let kdl = r#"
            retry-policy {
                max-attempts 3
                timeout-ms 0
                backoff-base-ms 100
                backoff-max-ms 10000
                retryable-status-codes 502 503 504
            }
        "#;

        let doc: kdl::KdlDocument = kdl.parse().unwrap();
        let rp_node = doc.get("retry-policy").unwrap();

        let rp = parse_retry_policy(rp_node);
        let err_msg = rp.unwrap_err();
        assert_eq!(format!("{}", err_msg), "Implausible value for timeout-ms");
    }

    /// retry-policy stanza present, one value parse-error (negative), expect to Err from TryFromIntError
    #[test]
    fn test_parse_retry_policy_parseerr_u64_check() {
        let kdl = r#"
            retry-policy {
                max-attempts 3
                timeout-ms -30000
                backoff-base-ms 100
                backoff-max-ms 10000
                retryable-status-codes 502 503 504
            }
        "#;

        let doc: kdl::KdlDocument = kdl.parse().unwrap();
        let rp_node = doc.get("retry-policy").unwrap();

        let rp = parse_retry_policy(rp_node);
        let err_msg = rp.unwrap_err();
        assert_eq!(
            format!("{}", err_msg),
            "out of range integral type conversion attempted"
        );
    }

    /// retry-policy stanza present, bad status value, return Err
    #[test]
    fn test_parse_retry_policy_badstatuscode() {
        let kdl = r#"
            retry-policy {
                max-attempts 3
                timeout-ms 30000
                backoff-base-ms 100
                backoff-max-ms 10000
                retryable-status-codes 502 888 504
            }
        "#;

        let doc: kdl::KdlDocument = kdl.parse().unwrap();
        let rp_node = doc.get("retry-policy").unwrap();

        let rp = parse_retry_policy(rp_node);
        let err_msg = rp.unwrap_err();
        assert_eq!(
            format!("{}", err_msg),
            "Status code 888 is not a valid code"
        );
    }

    /// retry-policy stanza present, all values missing, defaults should be used
    #[test]
    fn test_parse_retry_policy_fields_missing() {
        let kdl = r#"
            retry-policy {
            }
        "#;

        let doc: kdl::KdlDocument = kdl.parse().unwrap();
        let rp_node = doc.get("retry-policy").unwrap();

        let rp = parse_retry_policy(rp_node).unwrap();

        let default_rp = RetryPolicy::default();

        assert_eq!(rp.max_attempts, default_rp.max_attempts);
        assert_eq!(rp.timeout_ms, default_rp.timeout_ms);
        assert_eq!(rp.backoff_base_ms, default_rp.backoff_base_ms);
        assert_eq!(rp.backoff_max_ms, default_rp.backoff_max_ms);
        assert_eq!(rp.retryable_status_codes, default_rp.retryable_status_codes);
    }

    /// retry-policy stanza present, some values missing, defaults should be used for missing
    #[test]
    fn test_parse_retry_policy_some_fields_missing() {
        let kdl = r#"
            retry-policy {
                timeout-ms 1234
            }
        "#;

        let doc: kdl::KdlDocument = kdl.parse().unwrap();
        let rp_node = doc.get("retry-policy").unwrap();

        let rp = parse_retry_policy(rp_node).unwrap();

        let default_rp = RetryPolicy::default();

        assert_eq!(rp.max_attempts, default_rp.max_attempts);
        assert_eq!(rp.timeout_ms, 1234);
        assert_eq!(rp.backoff_base_ms, default_rp.backoff_base_ms);
        assert_eq!(rp.backoff_max_ms, default_rp.backoff_max_ms);
        assert_eq!(rp.retryable_status_codes, default_rp.retryable_status_codes);
    }
}
