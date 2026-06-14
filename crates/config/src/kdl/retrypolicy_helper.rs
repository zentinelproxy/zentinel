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
            d => {
                return Err(anyhow::anyhow!("Got unknown key {}", d));
            }
        }

        Ok(cfg)
    }

    node.iter_children().try_fold(default_config, rp_config_map)
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
        assert_eq!(format!("{}", err_msg), "Got unknown key max-attempt");
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
        assert_eq!(format!("{}", err_msg), "Got unknown key frob");
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
            "out of range integral type conversion attempted"
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
            "out of range integral type conversion attempted"
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
