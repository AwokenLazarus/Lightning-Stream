//! UnifiedSighash against the 166 reference vectors of Bitcoin Knots (`vectors/unified_sighash.json`,
//! see THIRD_PARTY_NOTICES.md): every script type and hash type, byte for byte.
use xbt_primitives::hash::tagged_hash;
use xbt_primitives::sighash::{unified_sighash, ScriptType};
use xbt_primitives::tx::{Tx, TxOut};

fn hex_of(v: &serde_json::Value) -> Vec<u8> {
    hex::decode(v.as_str().unwrap()).unwrap()
}

#[test]
fn every_knots_vector_is_byte_identical() {
    let path = concat!(env!("CARGO_MANIFEST_DIR"), "/../../vectors/unified_sighash.json");
    let v: serde_json::Value = serde_json::from_str(&std::fs::read_to_string(path).unwrap()).unwrap();
    // the first row names the columns
    let rows = &v.as_array().unwrap()[1..];
    assert_eq!(rows.len(), 166);
    for (n, row) in rows.iter().enumerate() {
        let script = hex_of(&row[0]);
        let tx = Tx::parse_hex(row[1].as_str().unwrap()).unwrap();
        let prevouts: Vec<TxOut> = row[5].as_array().unwrap().iter().map(|p| TxOut::new(p[0].as_i64().unwrap(), hex_of(&p[1]))).collect();
        let st = ScriptType::from_u8(row[4].as_u64().unwrap() as u8).unwrap();
        let mut leaf_in = vec![0xc0];
        xbt_primitives::encode::write_varbytes(&mut leaf_in, &script);
        let leaf = tagged_hash("TapLeaf", &leaf_in);
        let got = unified_sighash(&tx, &prevouts, row[2].as_u64().unwrap() as usize, st, &script, (row[3].as_i64().unwrap() & 0xFF) as u8,
                                  (st == ScriptType::Tapscript).then_some(&leaf)).unwrap();
        assert_eq!(hex::encode(got), row[6].as_str().unwrap(), "vector {n}");
    }
}
