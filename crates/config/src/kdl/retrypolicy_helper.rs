use anyhow::Result;
use zentinel_common::types::RetryPolicy;

use crate::kdl::helpers::extract_u32_with_limits;

pub fn parse_retry_policy(node: &kdl::KdlNode) -> Result<RetryPolicy> {
    let default_config = RetryPolicy::default();

    fn rp_config_map(mut cfg: RetryPolicy, node: &kdl::KdlNode) -> Result<RetryPolicy> {
        match node.name().to_string().as_str() {
            "max-attempts" => {
                cfg.max_attempts = extract_u32_with_limits(node)?;
            }
            "retryable-status-codes" => {
                let mut codes = Vec::new();
                for entry in node.entries() {
                    let code = entry.value().as_integer().ok_or_else(|| {
                        anyhow::anyhow!(
                            "retryable-status-codes takes status codes as numbers, \
                             for example: retryable-status-codes 502 503 504"
                        )
                    })?;
                    let code = u16::try_from(code).ok().filter(|c| (100..=599).contains(c));
                    match code {
                        Some(c) => codes.push(c),
                        None => {
                            return Err(anyhow::anyhow!(
                                "retryable-status-codes contains a value that is not an \
                                 HTTP status code (100-599)"
                            ))
                        }
                    }
                }
                if codes.is_empty() {
                    return Err(anyhow::anyhow!(
                        "retryable-status-codes was given no status codes; omit the node \
                         instead of leaving it empty"
                    ));
                }
                cfg.retryable_status_codes = codes;
            }
            "backoff" => {
                cfg.backoff = parse_retry_duration(node, "backoff")?;
            }
            "max-backoff" => {
                cfg.max_backoff = parse_retry_duration(node, "max-backoff")?;
            }
            "per-attempt-timeout" => {
                cfg.per_attempt_timeout = Some(parse_retry_duration(node, "per-attempt-timeout")?);
            }
            "retry-non-idempotent" => {
                cfg.retry_non_idempotent = node
                    .entries()
                    .first()
                    .and_then(|e| e.value().as_bool())
                    .ok_or_else(|| {
                        anyhow::anyhow!(
                            "retry-non-idempotent takes a boolean, for example: \
                             retry-non-idempotent #true"
                        )
                    })?;
            }
            d => {
                return Err(anyhow::anyhow!(
                    "Unknown key '{}' in retry-policy. Valid keys are: max-attempts, \
                     retryable-status-codes, backoff, max-backoff, per-attempt-timeout, \
                     retry-non-idempotent",
                    d
                ));
            }
        }

        Ok(cfg)
    }

    let policy = node
        .iter_children()
        .try_fold(default_config, rp_config_map)?;

    // A doubling backoff that starts above its own ceiling never doubles, so
    // the ceiling silently becomes the only delay. Say so rather than let the
    // config imply a ramp that cannot happen.
    if policy.backoff > policy.max_backoff {
        return Err(anyhow::anyhow!(
            "retry-policy backoff ({:?}) is greater than max-backoff ({:?}); \
             the backoff would never grow",
            policy.backoff,
            policy.max_backoff
        ));
    }

    Ok(policy)
}

/// Parse a duration node such as `backoff "250ms"`.
fn parse_retry_duration(node: &kdl::KdlNode, key: &str) -> Result<std::time::Duration> {
    let text = node
        .entries()
        .first()
        .and_then(|e| e.value().as_string())
        .ok_or_else(|| {
            anyhow::anyhow!("{key} takes a duration string, for example: {key} \"250ms\"")
        })?;
    parse_short_duration(text).ok_or_else(|| {
        anyhow::anyhow!(
            "{key} has an invalid duration '{text}'. Use a value such as \"250ms\", \
             \"2s\" or \"1m\""
        )
    })
}

/// Durations here are usually sub-second, which the shared seconds-resolution
/// parser cannot express -- a `100ms` backoff would round to zero.
fn parse_short_duration(text: &str) -> Option<std::time::Duration> {
    let text = text.trim();
    let idx = text.find(|c: char| c.is_alphabetic())?;
    let (value, unit) = text.split_at(idx);
    let value: f64 = value.trim().parse().ok()?;
    if value < 0.0 || !value.is_finite() {
        return None;
    }
    let millis = match unit.trim().to_ascii_lowercase().as_str() {
        "ms" => value,
        "s" | "sec" | "secs" => value * 1_000.0,
        "m" | "min" | "mins" => value * 60_000.0,
        _ => return None,
    };
    Some(std::time::Duration::from_millis(millis as u64))
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
            }
        "#;

        let doc: kdl::KdlDocument = kdl.parse().unwrap();
        let rp_node = doc.get("retry-policy").unwrap();

        let rp = parse_retry_policy(rp_node).unwrap();

        assert_eq!(rp.max_attempts, 10);
    }

    /// retry-policy stanza present, one key unrecognized, expect to Err and panic out
    #[test]
    fn test_parse_retry_policy_badkey() {
        let kdl = r#"
            retry-policy {
                max-attempt 3
            }
        "#;

        let doc: kdl::KdlDocument = kdl.parse().unwrap();
        let rp_node = doc.get("retry-policy").unwrap();

        let rp = parse_retry_policy(rp_node);
        let err_msg = rp.unwrap_err();
        assert_eq!(format!("{}", err_msg), "Unknown key 'max-attempt' in retry-policy. Valid keys are: max-attempts, retryable-status-codes, backoff, max-backoff, per-attempt-timeout, retry-non-idempotent");
    }

    /// retry-policy stanza present, new key unrecognized, expect to Err and panic out
    #[test]
    fn test_parse_retry_policy_badnewkey() {
        let kdl = r#"
            retry-policy {
                max-attempts 3
                frob 30000
            }
        "#;

        let doc: kdl::KdlDocument = kdl.parse().unwrap();
        let rp_node = doc.get("retry-policy").unwrap();

        let rp = parse_retry_policy(rp_node);
        let err_msg = rp.unwrap_err();
        assert_eq!(format!("{}", err_msg), "Unknown key 'frob' in retry-policy. Valid keys are: max-attempts, retryable-status-codes, backoff, max-backoff, per-attempt-timeout, retry-non-idempotent");
    }

    /// retry-policy stanza present, one value unrecognized, expect to Err and panic out
    #[test]
    fn test_parse_retry_policy_badval() {
        let kdl = r#"
            retry-policy {
                max-attempts "three"
            }
        "#;

        let doc: kdl::KdlDocument = kdl.parse().unwrap();
        let rp_node = doc.get("retry-policy").unwrap();

        let rp = parse_retry_policy(rp_node);
        let err_msg = rp.unwrap_err();
        assert_eq!(
            format!("{}", err_msg),
            "Tried to convert value in max-attempts to u32, but failed"
        );
    }

    /// retry-policy stanza present, one value out-of-bounds(0), expect to Err and crash
    #[test]
    fn test_parse_retry_policy_u32_check() {
        let kdl = r#"
            retry-policy {
                max-attempts 0
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
            }
        "#;

        let doc: kdl::KdlDocument = kdl.parse().unwrap();
        let rp_node = doc.get("retry-policy").unwrap();

        let rp = parse_retry_policy(rp_node);
        let err_msg = rp.unwrap_err();
        assert_eq!(
            format!("{}", err_msg),
            // std's own message: its wording changed in Rust 1.99.
            u32::try_from(u64::MAX).unwrap_err().to_string()
        );
    }

    /// retry-policy stanza present, one value parse-error (negative), expect to Err from TryFromIntError
    #[test]
    fn test_parse_retry_policy_parseerr_u32_check() {
        let kdl = r#"
            retry-policy {
                max-attempts -4
            }
        "#;

        let doc: kdl::KdlDocument = kdl.parse().unwrap();
        let rp_node = doc.get("retry-policy").unwrap();

        let rp = parse_retry_policy(rp_node);
        let err_msg = rp.unwrap_err();
        assert_eq!(
            format!("{}", err_msg),
            // std's own message: its wording changed in Rust 1.99.
            u32::try_from(-1i64).unwrap_err().to_string()
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
    }
}

#[cfg(test)]
mod extended_tests {
    use super::parse_retry_policy;
    use std::time::Duration;

    fn parse(kdl: &str) -> Result<zentinel_common::types::RetryPolicy, String> {
        let doc: kdl::KdlDocument = kdl.parse().unwrap();
        let node = doc.get("retry-policy").unwrap();
        parse_retry_policy(node).map_err(|e| e.to_string())
    }

    #[test]
    fn full_policy_parses() {
        let p = parse(
            r#"
            retry-policy {
                max-attempts 4
                retryable-status-codes 502 503 504
                backoff "250ms"
                max-backoff "5s"
                per-attempt-timeout "1s"
                retry-non-idempotent #true
            }
        "#,
        )
        .expect("should parse");

        assert_eq!(p.max_attempts, 4);
        assert_eq!(p.retryable_status_codes, vec![502, 503, 504]);
        assert_eq!(p.backoff, Duration::from_millis(250));
        assert_eq!(p.max_backoff, Duration::from_secs(5));
        assert_eq!(p.per_attempt_timeout, Some(Duration::from_secs(1)));
        assert!(p.retry_non_idempotent);
    }

    /// Sub-second backoffs are the common case, so a parser that only
    /// understands whole seconds would round `100ms` to zero and quietly
    /// remove the spacing between retries.
    #[test]
    fn sub_second_durations_are_preserved() {
        let p = parse("retry-policy {\n backoff \"50ms\"\n}").unwrap();
        assert_eq!(p.backoff, Duration::from_millis(50));
    }

    #[test]
    fn a_backoff_above_its_ceiling_is_rejected() {
        // Otherwise the ceiling silently becomes the only delay and the
        // configured ramp never happens.
        let err = parse("retry-policy {\n backoff \"10s\"\n max-backoff \"1s\"\n}")
            .expect_err("should be rejected");
        assert!(err.contains("never grow"), "unexpected error: {err}");
    }

    #[test]
    fn a_non_status_code_is_rejected() {
        let err = parse("retry-policy {\n retryable-status-codes 700\n}")
            .expect_err("should be rejected");
        assert!(err.contains("100-599"), "unexpected error: {err}");
    }

    #[test]
    fn an_empty_status_code_list_is_rejected() {
        // An empty list reads as "retry on any status" but means "retry on
        // none", so it is better refused than misread.
        let err =
            parse("retry-policy {\n retryable-status-codes\n}").expect_err("should be rejected");
        assert!(err.contains("no status codes"), "unexpected error: {err}");
    }

    #[test]
    fn an_invalid_duration_is_rejected() {
        let err = parse("retry-policy {\n backoff \"soon\"\n}").expect_err("should be rejected");
        assert!(err.contains("invalid duration"), "unexpected error: {err}");
    }

    #[test]
    fn defaults_are_conservative() {
        let p = parse("retry-policy {\n max-attempts 3\n}").unwrap();
        assert!(
            p.retryable_status_codes.is_empty(),
            "no status should be retryable unless asked for"
        );
        assert!(
            !p.retry_non_idempotent,
            "replaying a POST should take a deliberate choice"
        );
        assert_eq!(p.per_attempt_timeout, None);
    }
}
