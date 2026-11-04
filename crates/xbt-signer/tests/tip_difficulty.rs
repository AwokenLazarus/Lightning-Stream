//! `mining_tip`'s difficulty from Knots before and after 29.4.3, which says `difficulty_blake2b` instead of `difficulty`.
use serde_json::{json, Value};
use xbt_signer::signer::tip_difficulty;

#[test]
fn an_older_knots_difficulty_is_taken_as_it_is() {
    assert_eq!(tip_difficulty(&json!({"difficulty": 6.33e9})), json!(6.33e9));
}

#[test]
fn knots_29_4_3_says_difficulty_blake2b_which_is_that_times_2_pow_32() {
    // mainnet block 980279: bits 1900ad98
    let d = tip_difficulty(&json!({"difficulty_blake2b": 2.72035512964588e19})).as_f64().unwrap();
    assert!((d - 6.333723711e9).abs() / 6.333723711e9 < 1e-4, "{d}");
}

#[test]
fn difficulty_wins_when_a_node_says_both() {
    assert_eq!(tip_difficulty(&json!({"difficulty": 5.0, "difficulty_blake2b": 1e19})), json!(5.0));
}

#[test]
fn nothing_usable_is_null() {
    for v in [json!({}), json!({"difficulty": 0}), json!({"difficulty_blake2b": -1.0}), json!({"difficulty": "x"})] {
        assert_eq!(tip_difficulty(&v), Value::Null, "{v}");
    }
}
