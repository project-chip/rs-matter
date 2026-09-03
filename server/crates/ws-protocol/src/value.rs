//! `MValue` <-> tag-based JSON, per WIRE_PROTOCOL.md §2/§24.
//!
//! This is the *schema-less* tag-based conversion matter.js calls
//! `convertMatterToWebSocketTagBased` (Converters.ts:346-431) with no `ValueModel` (the
//! `model === undefined` branch, Converters.ts:369-379): struct members are tagged by TLV
//! context tag (numeric string key) rather than field name, octet strings are base64 (not our
//! old `{"$bytes"}` wrapper), floats/u64 are bare JSON numbers, `null` passes through. See
//! `docs/WIRE_PROTOCOL.md` §24 for the full citation trail.

use base64::Engine as _;
use serde_json::{Number, Value as Json};

/// Backend-neutral decoded Matter value (TLV shape, tags preserved). Mirrors PLAN.md §3.
#[derive(Debug, Clone, PartialEq)]
pub enum MValue {
    Null,
    Bool(bool),
    U(u64),
    I(i64),
    F32(f32),
    F64(f64),
    Str(String),
    Bytes(Vec<u8>),
    Array(Vec<MValue>),
    /// Context tag -> value, in TLV member order.
    Struct(Vec<(u8, MValue)>),
}

fn b64() -> base64::engine::GeneralPurpose {
    base64::engine::general_purpose::STANDARD
}

impl MValue {
    /// Tag-based encode: struct keys are decimal-string context tags (WIRE_PROTOCOL.md §2).
    /// Octet strings become base64 (Converters.ts `Bytes.toBase64`, no wrapper object).
    pub fn to_json(&self) -> Json {
        match self {
            MValue::Null => Json::Null,
            MValue::Bool(b) => Json::Bool(*b),
            // u64/i64 round-trip losslessly through serde_json::Number (native u64/i64 storage),
            // matching matter.js's `toBigIntAwareJson`, which emits bigints as bare decimal digits.
            MValue::U(u) => Json::Number(Number::from(*u)),
            MValue::I(i) => Json::Number(Number::from(*i)),
            MValue::F32(f) => json_from_f64(*f as f64),
            MValue::F64(f) => json_from_f64(*f),
            MValue::Str(s) => Json::String(s.clone()),
            MValue::Bytes(b) => Json::String(b64().encode(b)),
            MValue::Array(items) => Json::Array(items.iter().map(MValue::to_json).collect()),
            MValue::Struct(members) => {
                let mut map = serde_json::Map::with_capacity(members.len());
                for (tag, val) in members {
                    map.insert(tag.to_string(), val.to_json());
                }
                Json::Object(map)
            }
        }
    }

    /// Tag-based decode. Object keys must be decimal `u8` context tags — schema-driven fallback
    /// to wire-field-name lookup (Converters.ts:427-443, for pre-1.3.0 python clients) is out of
    /// scope here: it needs a `ClusterModel`, which lives in `matter-names`, not this crate.
    ///
    /// A JSON string is decoded as `Str`: distinguishing an octet string from text requires the
    /// attribute's schema (matter.js dispatches on `model.metabase.metatype === "bytes"` before
    /// ever reaching the generic converter — Converters.ts:196-198), which this crate does not
    /// have. Callers that know a path is byte-typed should re-wrap a `Str` result as `Bytes`.
    pub fn from_json(j: &Json) -> Result<MValue, ValueError> {
        match j {
            Json::Null => Ok(MValue::Null),
            Json::Bool(b) => Ok(MValue::Bool(*b)),
            Json::Number(n) => {
                if let Some(u) = n.as_u64() {
                    Ok(MValue::U(u))
                } else if let Some(i) = n.as_i64() {
                    Ok(MValue::I(i))
                } else if let Some(f) = n.as_f64() {
                    Ok(MValue::F64(f))
                } else {
                    Err(ValueError::Unsupported)
                }
            }
            Json::String(s) => Ok(MValue::Str(s.clone())),
            Json::Array(items) => items
                .iter()
                .map(MValue::from_json)
                .collect::<Result<Vec<_>, _>>()
                .map(MValue::Array),
            Json::Object(map) => map
                .iter()
                .map(|(k, v)| {
                    let tag = k.parse::<u8>().map_err(|_| ValueError::BadTag(k.clone()))?;
                    Ok((tag, MValue::from_json(v)?))
                })
                .collect::<Result<Vec<_>, _>>()
                .map(MValue::Struct),
        }
    }
}

fn json_from_f64(f: f64) -> Json {
    Number::from_f64(f).map(Json::Number).unwrap_or(Json::Null)
}

#[derive(Debug, thiserror::Error)]
pub enum ValueError {
    #[error("object key '{0}' is not a valid decimal u8 context tag")]
    BadTag(String),
    #[error("unsupported JSON value for TLV conversion")]
    Unsupported,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn scalars_roundtrip() {
        for v in [
            MValue::Null,
            MValue::Bool(true),
            MValue::U(7),
            MValue::I(-3),
            MValue::Str("hi".into()),
            MValue::F64(1.5),
        ] {
            let j = v.to_json();
            assert_eq!(
                MValue::from_json(&j).unwrap(),
                v,
                "roundtrip failed for {j}"
            );
        }
    }

    #[test]
    fn u64_full_range_roundtrips_without_precision_loss() {
        // The exact value PLAN.md §8 requires: above 2^53, still an exact bare JSON integer.
        let v = MValue::U(18_446_744_069_414_584_320);
        let j = v.to_json();
        assert_eq!(j.to_string(), "18446744069414584320");
        assert_eq!(MValue::from_json(&j).unwrap(), v);

        let max = MValue::U(u64::MAX);
        assert_eq!(max.to_json().to_string(), u64::MAX.to_string());
        assert_eq!(MValue::from_json(&max.to_json()).unwrap(), max);
    }

    #[test]
    fn struct_roundtrips_with_numeric_tag_keys() {
        let v = MValue::Struct(vec![(0, MValue::U(1)), (1, MValue::Str("x".into()))]);
        let j = v.to_json();
        assert_eq!(j, serde_json::json!({"0": 1, "1": "x"}));
        assert_eq!(MValue::from_json(&j).unwrap(), v);
    }

    #[test]
    fn list_roundtrips() {
        let v = MValue::Array(vec![MValue::U(1), MValue::U(2), MValue::U(3)]);
        let j = v.to_json();
        assert_eq!(j, serde_json::json!([1, 2, 3]));
        assert_eq!(MValue::from_json(&j).unwrap(), v);
    }

    #[test]
    fn bytes_encode_as_bare_base64_no_wrapper() {
        // Converters.ts: Bytes.toBase64(value) - a bare string, never {"$bytes": ...}.
        let v = MValue::Bytes(vec![0x00, 0xff, 0x10]);
        let j = v.to_json();
        assert_eq!(j, Json::String("AP8Q".into()));
        // Decoding a bare string yields Str (schema-less ambiguity, documented above);
        // the caller reinterprets it as Bytes when it knows the attribute is octet-string typed.
        assert_eq!(MValue::from_json(&j).unwrap(), MValue::Str("AP8Q".into()));
    }

    #[test]
    fn non_numeric_struct_key_is_an_error() {
        let j = serde_json::json!({"name": 1});
        assert!(MValue::from_json(&j).is_err());
    }

    #[test]
    fn nested_struct_and_list_roundtrip() {
        let v = MValue::Struct(vec![
            (0, MValue::Array(vec![MValue::U(1), MValue::U(2)])),
            (1, MValue::Struct(vec![(0, MValue::Bool(false))])),
        ]);
        let j = v.to_json();
        assert_eq!(j, serde_json::json!({"0": [1, 2], "1": {"0": false}}));
        assert_eq!(MValue::from_json(&j).unwrap(), v);
    }
}
