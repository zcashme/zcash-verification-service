//! Fee policy for OTP response transactions.
//!
//! Fees follow ZIP 317, but the marginal fee ("standard fee per logical action")
//! is a node policy that can differ from the compiled-in constant. With the
//! `zebra-indexer` build, the worker asks the node for it once at boot with the
//! `getstandardfee` RPC and builds the wallet's fee rule from the answer. If the
//! node cannot answer (older node, lightwalletd build, RPC error, or an
//! implausible value), the worker falls back to the compiled-in ZIP 317 rule,
//! which can only overpay.

use anyhow::{anyhow, Result};
use serde::Deserialize;
use zcash_primitives::transaction::fees::zip317::{
    FeeRule, GRACE_ACTIONS, MARGINAL_FEE, P2PKH_STANDARD_INPUT_SIZE, P2PKH_STANDARD_OUTPUT_SIZE,
};
use zcash_protocol::value::Zatoshis;

/// Largest marginal fee we accept from a node: ten times the ZIP 317 constant.
/// A larger value is treated as a misbehaving node, not a policy.
pub const MAX_MARGINAL_FEE_ZATS: u64 = 10 * 5_000;

/// The `getstandardfee` RPC result.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
pub struct StandardFee {
    /// Recommended fee per logical action, in zatoshis.
    pub standard_fee: u64,
    /// Result-shape/estimator version reported by the node.
    #[serde(default)]
    pub version: u32,
}

/// Build a ZIP 317 fee rule whose marginal fee is the node's standard fee.
pub fn rule_from_standard_fee(fee: StandardFee) -> Result<FeeRule> {
    if fee.standard_fee == 0 || fee.standard_fee > MAX_MARGINAL_FEE_ZATS {
        return Err(anyhow!(
            "node standard fee {} zats is outside the accepted range 1..={}",
            fee.standard_fee,
            MAX_MARGINAL_FEE_ZATS
        ));
    }
    let marginal = Zatoshis::from_u64(fee.standard_fee)
        .map_err(|e| anyhow!("invalid node standard fee: {e}"))?;
    FeeRule::non_standard(
        marginal,
        GRACE_ACTIONS,
        P2PKH_STANDARD_INPUT_SIZE,
        P2PKH_STANDARD_OUTPUT_SIZE,
    )
    .ok_or_else(|| anyhow!("could not construct a ZIP 317 fee rule"))
}

/// The compiled-in ZIP 317 rule, used when the node cannot supply a policy.
pub fn fallback_rule() -> FeeRule {
    FeeRule::standard()
}

/// The compiled-in ZIP 317 marginal fee, for logging.
pub fn fallback_marginal_fee_zats() -> u64 {
    MARGINAL_FEE.into_u64()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_the_zakura_response() {
        let fee: StandardFee =
            serde_json::from_str(r#"{"standard_fee":400,"version":0}"#).expect("valid result");
        assert_eq!(
            fee,
            StandardFee {
                standard_fee: 400,
                version: 0
            }
        );
    }

    #[test]
    fn version_is_optional() {
        let fee: StandardFee = serde_json::from_str(r#"{"standard_fee":400}"#).unwrap();
        assert_eq!(fee.version, 0);
    }

    #[test]
    fn builds_a_rule_with_the_node_marginal_fee() {
        let rule = rule_from_standard_fee(StandardFee {
            standard_fee: 400,
            version: 0,
        })
        .unwrap();
        assert_eq!(rule.marginal_fee().into_u64(), 400);
        assert_eq!(rule.grace_actions(), GRACE_ACTIONS);
    }

    #[test]
    fn fallback_is_the_standard_zip317_rule() {
        let rule = fallback_rule();
        assert_eq!(rule.marginal_fee(), MARGINAL_FEE);
        assert_eq!(rule.grace_actions(), GRACE_ACTIONS);
        assert_eq!(fallback_marginal_fee_zats(), 5_000);
    }

    #[test]
    fn rejects_implausible_values() {
        assert!(rule_from_standard_fee(StandardFee {
            standard_fee: 0,
            version: 0
        })
        .is_err());
        assert!(rule_from_standard_fee(StandardFee {
            standard_fee: MAX_MARGINAL_FEE_ZATS + 1,
            version: 0
        })
        .is_err());
        assert!(rule_from_standard_fee(StandardFee {
            standard_fee: MAX_MARGINAL_FEE_ZATS,
            version: 0
        })
        .is_ok());
    }
}
