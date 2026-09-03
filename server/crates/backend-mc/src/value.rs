//! `matter_codec::Value` <-> `ws_protocol::MValue`. Both are the same TLV shape (scalars, an
//! octet-string variant, an array, and a context-tagged struct) so this is a structural mapping
//! with one lossy corner: `matter_codec::Value` is `#[non_exhaustive]` (it may grow variants in a
//! semver-compatible matter-codec release) and additionally has a `List` variant (heterogeneous,
//! possibly non-context tags) that `MValue` has no equivalent for. Every value this backend
//! actually reads from `Node::read`/`Subscription` and every value it builds for
//! `Node::write`/`Node::invoke` is a `Structure`/`Array`/scalar in practice (Matter's IM never
//! puts a `List` at the top of an attribute or command-field value), so the `List` and
//! catch-all arms below are defensive, not load-bearing.

use matter_codec::{Tag, Value};
use ws_protocol::MValue;

/// `Value` -> `MValue`. Struct/list members keep only `Tag::Context(_)` entries (WIRE_PROTOCOL.md
/// §2/§24: the wire's tag-based shape is *always* keyed by numeric context tag); a member under
/// any other tag form is dropped with a warning -- Matter's Interaction Model never emits
/// anything else at the application-data layer, so this only fires on a malformed/future device.
pub fn value_to_mvalue(v: &Value) -> MValue {
    match v {
        Value::Null => MValue::Null,
        Value::Bool(b) => MValue::Bool(*b),
        Value::Uint(u) => MValue::U(*u),
        Value::Int(i) => MValue::I(*i),
        Value::Float(f) => MValue::F32(*f),
        Value::Double(d) => MValue::F64(*d),
        Value::Utf8(s) => MValue::Str(s.clone()),
        Value::Bytes(b) => MValue::Bytes(b.clone()),
        Value::Array(items) => MValue::Array(items.iter().map(value_to_mvalue).collect()),
        // `List` shares `Structure`'s member shape (`opcreds.rs`/`acl.rs` in matter-controller
        // itself treat them identically via a shared `struct_members` helper) -- fold both here.
        Value::Structure(members) | Value::List(members) => MValue::Struct(context_tagged(members)),
        // Non-exhaustive upstream enum: an unrecognised future variant degrades to Null rather
        // than panicking or silently dropping the whole read.
        other => {
            tracing::warn!(
                ?other,
                "unhandled matter_codec::Value variant, mapping to MValue::Null"
            );
            MValue::Null
        }
    }
}

fn context_tagged(members: &[(Tag, Value)]) -> Vec<(u8, MValue)> {
    members
        .iter()
        .filter_map(|(tag, v)| match tag {
            Tag::Context(t) => Some((*t, value_to_mvalue(v))),
            other => {
                tracing::warn!(?other, "dropping non-context-tagged struct member");
                None
            }
        })
        .collect()
}

/// `MValue` -> `Value`, for building write/invoke payloads. The exact inverse of the scalar/array/
/// struct arms above (there is no `MValue` shape that produces a `List`: this backend only ever
/// writes `Structure`s).
pub fn mvalue_to_value(v: &MValue) -> Value {
    match v {
        MValue::Null => Value::Null,
        MValue::Bool(b) => Value::Bool(*b),
        MValue::U(u) => Value::Uint(*u),
        MValue::I(i) => Value::Int(*i),
        MValue::F32(f) => Value::Float(*f),
        MValue::F64(f) => Value::Double(*f),
        MValue::Str(s) => Value::Utf8(s.clone()),
        MValue::Bytes(b) => Value::Bytes(b.clone()),
        MValue::Array(items) => Value::Array(items.iter().map(mvalue_to_value).collect()),
        MValue::Struct(members) => Value::Structure(
            members
                .iter()
                .map(|(t, v)| (Tag::Context(*t), mvalue_to_value(v)))
                .collect(),
        ),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn scalars_roundtrip() {
        for v in [
            Value::Null,
            Value::Bool(true),
            Value::Uint(7),
            Value::Int(-3),
            Value::Float(1.5),
            Value::Double(2.5),
            Value::Utf8("hi".into()),
            Value::Bytes(vec![1, 2, 3]),
        ] {
            let m = value_to_mvalue(&v);
            assert_eq!(mvalue_to_value(&m), v, "roundtrip failed for {v:?}");
        }
    }

    #[test]
    fn struct_and_array_roundtrip() {
        let v = Value::Structure(vec![
            (Tag::Context(0), Value::Uint(1)),
            (
                Tag::Context(1),
                Value::Array(vec![Value::Bool(false), Value::Utf8("x".into())]),
            ),
        ]);
        let m = value_to_mvalue(&v);
        assert_eq!(
            m,
            MValue::Struct(vec![
                (0, MValue::U(1)),
                (
                    1,
                    MValue::Array(vec![MValue::Bool(false), MValue::Str("x".into())])
                ),
            ])
        );
        assert_eq!(mvalue_to_value(&m), v);
    }

    #[test]
    fn list_folds_into_struct_like_structure() {
        let v = Value::List(vec![(Tag::Context(2), Value::Uint(9))]);
        assert_eq!(value_to_mvalue(&v), MValue::Struct(vec![(2, MValue::U(9))]));
    }

    #[test]
    fn non_context_tag_is_dropped_not_fatal() {
        let v = Value::Structure(vec![
            (Tag::Anonymous, Value::Uint(1)),
            (Tag::Context(5), Value::Uint(2)),
        ]);
        assert_eq!(value_to_mvalue(&v), MValue::Struct(vec![(5, MValue::U(2))]));
    }

    #[test]
    fn octet_string_roundtrips_as_bytes_not_text() {
        let v = Value::Bytes(vec![0, 255, 16]);
        let m = value_to_mvalue(&v);
        assert_eq!(m, MValue::Bytes(vec![0, 255, 16]));
        // And through MValue's own wire encoding this is bare base64 (WIRE_PROTOCOL.md §24) --
        // exercising that here pins the whole round trip a `device_command`/`read_attribute`
        // response actually takes.
        assert_eq!(m.to_json(), serde_json::json!("AP8Q"));
    }
}
