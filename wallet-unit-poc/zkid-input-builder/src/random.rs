//! Per-session blinding factor for `pk_commit`. See
//! `wallet-unit-poc/circom/SPEC.md` §Linking for the security rationale.

use num_bigint::BigUint;

/// Returns a uniformly random 248-bit field element (decimal string), suitable
/// as the `pk_blind` input to both cert-chain and user-sig circuits.
///
/// 248 bits is below the secq256r1 scalar-field modulus (≈ 2^256), so the value
/// passes through circom without modular reduction.
pub fn random_pk_blind() -> String {
    let mut buf = [0u8; 31];
    getrandom::getrandom(&mut buf).expect("OS RNG unavailable");
    BigUint::from_bytes_be(&buf).to_string()
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::str::FromStr;

    #[test]
    fn random_pk_blind_is_in_field_range() {
        let v = BigUint::from_str(&random_pk_blind()).expect("decimal");
        let upper_bound = BigUint::from(1u8) << 248;
        assert!(v < upper_bound, "blind exceeded 2^248: {v}");
    }

    #[test]
    fn random_pk_blind_distinct_across_calls() {
        let a = random_pk_blind();
        let b = random_pk_blind();
        let c = random_pk_blind();
        assert_ne!(a, b);
        assert_ne!(b, c);
        assert_ne!(a, c);
    }
}
