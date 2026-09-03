//! Matter IDL name table for the Home Assistant WebSocket wire format.
//!
//! Names are needed in exactly three places (PLAN.md §2): the
//! `device_command.command_name` lookup, the `device_command.payload` +
//! response fields, and `node_event.data`. Attribute *values* are tag-based and
//! never need field names, so only the attribute id → name map is generated.
//!
//! The crate is deliberately backend- and protocol-agnostic: it converts
//! between [`serde_json::Value`] and the local TLV-shaped [`Tlv`]. The
//! integrating crate owns the conversion between [`Tlv`] and its own value
//! model (`ws-protocol::MValue`).

pub mod codegen;
pub mod table;

#[allow(clippy::all)]
mod generated {
    include!("generated.rs");
}

use serde_json::{Map, Value};

pub use generated::CLUSTERS;
pub use table::{Bitmap, BitmapMember, Cluster, Command, Event, Field, Kind, Struct};

/// TLV-shaped value. Mirrors `ws-protocol::MValue` without depending on it.
#[derive(Debug, Clone, PartialEq)]
pub enum Tlv {
    Null,
    Bool(bool),
    U(u64),
    I(i64),
    F32(f32),
    F64(f64),
    Str(String),
    Bytes(Vec<u8>),
    Array(Vec<Tlv>),
    Struct(Vec<(u8, Tlv)>),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum NameError {
    /// No such cluster, or no command with that (camelized) name on it.
    UnknownCommand { cluster: u32, command: String },
    /// A payload key that no field of the command accepts.
    UnknownField { field: String },
    /// A mandatory field the payload did not carry.
    MissingField { field: String },
    /// The JSON value cannot be coerced to the field's wire type.
    TypeMismatch {
        field: String,
        expected: &'static str,
    },
    /// `payload` was neither an object nor null.
    InvalidPayload,
}

impl std::fmt::Display for NameError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::UnknownCommand { cluster, command } => {
                write!(f, "unknown command {command:?} on cluster {cluster}")
            }
            Self::UnknownField { field } => write!(f, "unknown payload field {field:?}"),
            Self::MissingField { field } => write!(f, "missing mandatory field {field:?}"),
            Self::TypeMismatch { field, expected } => {
                write!(f, "field {field:?} is not a valid {expected}")
            }
            Self::InvalidPayload => write!(f, "payload must be an object"),
        }
    }
}

impl std::error::Error for NameError {}

// ---------------------------------------------------------------------------
// camelize
// ---------------------------------------------------------------------------

/// Port of matter.js `camelize` (`@matter/general` src/util/identifier-case.ts:21).
///
/// `WebSocketControllerHandler.ts:1233` runs every `command_name` through it and
/// `Converters.ts:154` every payload key, so our lookup keys must agree
/// character for character — including the `100ths` special case and the
/// stop-at-`$` behaviour.
pub fn camelize(name: &str) -> String {
    camelize_with(name, false)
}

/// `camelize(name, upperFirst)`.
pub fn camelize_with(name: &str, upper_first: bool) -> String {
    let chars: Vec<char> = name.chars().collect();
    let mut s = Splitter {
        chars: &chars,
        pieces: Vec::new(),
        start: 0,
        upper: false,
        lower: false,
    };
    let mut i = 0usize;

    while i < chars.len() {
        let c = chars[i];
        if c == '$' {
            break;
        }
        if c.is_ascii_uppercase() {
            if s.lower {
                s.cut(i);
                s.start = i;
            }
            s.upper = true;
        } else if c.is_ascii_lowercase() {
            if !s.lower && s.upper {
                s.cut(i - 1);
                s.start = i - 1;
            }
            s.lower = true;
        } else {
            s.cut(i);
            if c.is_ascii_digit() {
                s.pieces.push(&chars[i..i + 1]);
            }
            s.start = i + 1;
        }
        i += 1;
    }
    s.cut(i);

    let mut did_first = false;
    let mut result = String::new();
    for piece in &s.pieces {
        let (first, rest) = piece
            .split_first()
            .expect("cut never pushes an empty piece");
        if upper_first || did_first {
            result.extend(first.to_uppercase());
        } else {
            result.extend(first.to_lowercase());
            did_first = true;
        }
        result.extend(rest.iter().flat_map(|c| c.to_lowercase()));
    }

    result = fix_hundredths(&result);

    if i < chars.len() {
        result.extend(chars[i..].iter());
    }
    result
}

/// The `addPiece` closure of matter.js's `camelize`: closes the piece that
/// started at `start` and resets the case flags.
struct Splitter<'a> {
    chars: &'a [char],
    pieces: Vec<&'a [char]>,
    start: usize,
    upper: bool,
    lower: bool,
}

impl Splitter<'_> {
    fn cut(&mut self, to: usize) {
        if self.start < to {
            self.pieces.push(&self.chars[self.start..to]);
        }
        self.upper = false;
        self.lower = false;
    }
}

/// matter.js: `result.replace(/(\d)Ths/i, "$1ths")` — first match only.
fn fix_hundredths(s: &str) -> String {
    let b = s.as_bytes();
    for i in 0..b.len() {
        if b[i].is_ascii_digit() && i + 4 <= b.len() && b[i + 1..i + 4].eq_ignore_ascii_case(b"ths")
        {
            let mut out = String::with_capacity(s.len());
            out.push_str(&s[..i + 1]);
            out.push_str("ths");
            out.push_str(&s[i + 4..]);
            return out;
        }
    }
    s.to_owned()
}

// ---------------------------------------------------------------------------
// Lookups
// ---------------------------------------------------------------------------

pub fn cluster(id: u32) -> Option<&'static Cluster> {
    CLUSTERS
        .binary_search_by_key(&id, |c| c.id)
        .ok()
        .map(|i| &CLUSTERS[i])
}

pub fn cluster_name(id: u32) -> Option<&'static str> {
    cluster(id).map(|c| c.name)
}

pub fn attribute_name(cluster_id: u32, attribute: u32) -> Option<&'static str> {
    cluster(cluster_id)
        .and_then(|c| c.attribute(attribute))
        .or_else(|| {
            table::GLOBAL_ATTRIBUTES
                .iter()
                .find(|(id, _)| *id == attribute)
                .map(|(_, n)| *n)
        })
}

/// `command_name` is camelized before lookup, exactly as CCH:1082 does.
pub fn command_id(cluster_id: u32, command_name: &str) -> Option<u32> {
    command(cluster_id, command_name).map(|c| c.id)
}

/// Response command id, or `None` for a status-only command.
pub fn response_command_id(cluster_id: u32, command_name: &str) -> Option<u32> {
    command(cluster_id, command_name).and_then(|c| c.response_id)
}

pub fn event_name(cluster_id: u32, event_id: u32) -> Option<&'static str> {
    cluster(cluster_id)
        .and_then(|c| c.event(event_id))
        .map(|e| e.name)
}

fn command(cluster_id: u32, command_name: &str) -> Option<&'static Command> {
    cluster(cluster_id)?.command(&camelize(command_name))
}

// ---------------------------------------------------------------------------
// Encoding: JSON payload -> TLV
// ---------------------------------------------------------------------------

/// Resolve `command_name` and encode `payload` into the command's request struct.
///
/// Returns the numeric command id plus a [`Tlv::Struct`] with context tags in
/// ascending order. Mirrors `convertCommandDataToMatter` (Converters.ts:129).
pub fn encode_command(
    cluster_id: u32,
    command_name: &str,
    payload: &Value,
) -> Result<(u32, Tlv), NameError> {
    let cluster = cluster(cluster_id).ok_or_else(|| NameError::UnknownCommand {
        cluster: cluster_id,
        command: command_name.to_owned(),
    })?;
    let camel = camelize(command_name);
    let cmd = cluster.command(&camel).ok_or(NameError::UnknownCommand {
        cluster: cluster_id,
        command: camel,
    })?;
    let tlv = encode_struct(cluster, cmd.request, payload)?;
    Ok((cmd.id, tlv))
}

fn encode_struct(cluster: &Cluster, fields: &[Field], value: &Value) -> Result<Tlv, NameError> {
    let obj = match value {
        Value::Object(o) => Some(o),
        Value::Null => None,
        _ => return Err(NameError::InvalidPayload),
    };

    // Reject unknown keys the way matter.js's TLV encoder would; its converter
    // passes them through and the schema then rejects them (Converters.ts:164).
    for key in obj.iter().flat_map(|o| o.keys()) {
        let camel = camelize(key);
        if !fields
            .iter()
            .any(|f| f.prop() == camel || f.wire == camel || f.wire == *key)
        {
            return Err(NameError::UnknownField { field: key.clone() });
        }
    }

    let mut out = Vec::new();
    for f in fields {
        let Some(v) = obj.and_then(|o| lookup(o, f)) else {
            if f.optional() {
                continue;
            }
            return Err(NameError::MissingField {
                field: f.prop().to_owned(),
            });
        };
        if v.is_null() {
            if f.nullable() {
                out.push((f.tag, Tlv::Null));
                continue;
            }
            // Old Python clients send null for unset optional fields instead of
            // omitting them (Converters.ts:157).
            if f.optional() {
                continue;
            }
            return Err(NameError::TypeMismatch {
                field: f.prop().to_owned(),
                expected: "value",
            });
        }
        out.push((f.tag, encode_value(cluster, &f.kind, v, f.prop())?));
    }
    Ok(Tlv::Struct(out))
}

fn lookup<'a>(obj: &'a Map<String, Value>, f: &Field) -> Option<&'a Value> {
    if let Some(v) = obj.get(f.prop()) {
        return Some(v);
    }
    if let Some(v) = obj.get(f.wire) {
        return Some(v);
    }
    obj.iter()
        .find(|(k, _)| camelize(k) == f.prop())
        .map(|(_, v)| v)
}

fn encode_value(cluster: &Cluster, kind: &Kind, v: &Value, field: &str) -> Result<Tlv, NameError> {
    let mismatch = |expected| NameError::TypeMismatch {
        field: field.to_owned(),
        expected,
    };
    Ok(match kind {
        Kind::Bool => match v {
            Value::Bool(b) => Tlv::Bool(*b),
            Value::Number(n) => Tlv::Bool(n.as_u64().ok_or_else(|| mismatch("boolean"))? != 0),
            _ => return Err(mismatch("boolean")),
        },
        Kind::U | Kind::Enum => Tlv::U(as_u64(v).ok_or_else(|| mismatch("unsigned integer"))?),
        Kind::I => Tlv::I(as_i64(v).ok_or_else(|| mismatch("signed integer"))?),
        Kind::F32 => Tlv::F32(as_f64(v).ok_or_else(|| mismatch("float"))? as f32),
        Kind::F64 => Tlv::F64(as_f64(v).ok_or_else(|| mismatch("float"))?),
        Kind::Str => match v {
            Value::String(s) => Tlv::Str(s.clone()),
            _ => return Err(mismatch("string")),
        },
        Kind::OctStr => Tlv::Bytes(as_bytes(v).ok_or_else(|| mismatch("octet string"))?),
        Kind::Bitmap(idx) => {
            let bitmap = &cluster.bitmaps[*idx as usize];
            match v {
                Value::Object(_) => {
                    Tlv::U(pack_bitmap(bitmap, v).ok_or_else(|| mismatch("bitmap"))?)
                }
                _ => Tlv::U(as_u64(v).ok_or_else(|| mismatch("bitmap"))?),
            }
        }
        Kind::Struct(idx) => {
            let s = &cluster.structs[*idx as usize];
            match v {
                Value::Object(_) => encode_struct(cluster, s.fields, v)?,
                _ => return Err(mismatch("struct")),
            }
        }
        Kind::List(inner) => match v {
            Value::Array(items) => {
                let mut out = Vec::with_capacity(items.len());
                for item in items {
                    out.push(if item.is_null() {
                        Tlv::Null
                    } else {
                        encode_value(cluster, inner, item, field)?
                    });
                }
                Tlv::Array(out)
            }
            _ => return Err(mismatch("list")),
        },
    })
}

/// `convertWebSocketGenericToMatter` (Converters.ts:22) turns a flag object into
/// the packed integer the TLV codec wants.
fn pack_bitmap(bitmap: &Bitmap, v: &Value) -> Option<u64> {
    let obj = v.as_object()?;
    let mut packed = 0u64;
    for (key, value) in obj {
        let camel = camelize(key);
        let member = bitmap.members.iter().find(|m| m.name == camel)?;
        match value {
            Value::Bool(false) | Value::Null => {}
            Value::Bool(true) => packed |= member.mask,
            Value::Number(_) => {
                let n = as_u64(value)?;
                packed |= (n << member.mask.trailing_zeros()) & member.mask;
            }
            _ => return None,
        }
    }
    Some(packed)
}

fn as_u64(v: &Value) -> Option<u64> {
    match v {
        Value::Number(n) => n.as_u64().or_else(|| {
            n.as_f64()
                .filter(|f| f.fract() == 0.0 && *f >= 0.0)
                .map(|f| f as u64)
        }),
        Value::Bool(b) => Some(*b as u64),
        // 64-bit ids from clients that serialise them as strings.
        Value::String(s) => parse_int(s).and_then(|i| u64::try_from(i).ok()),
        _ => None,
    }
}

fn as_i64(v: &Value) -> Option<i64> {
    match v {
        Value::Number(n) => n
            .as_i64()
            .or_else(|| n.as_f64().filter(|f| f.fract() == 0.0).map(|f| f as i64)),
        Value::Bool(b) => Some(*b as i64),
        Value::String(s) => parse_int(s),
        _ => None,
    }
}

fn as_f64(v: &Value) -> Option<f64> {
    match v {
        Value::Number(n) => n.as_f64(),
        Value::String(s) => s.parse().ok(),
        _ => None,
    }
}

fn parse_int(s: &str) -> Option<i64> {
    let s = s.trim();
    match s.strip_prefix("0x").or_else(|| s.strip_prefix("0X")) {
        Some(hex) => i64::from_str_radix(hex, 16).ok(),
        None => s.parse().ok(),
    }
}

/// Octet strings travel as base64 (`Bytes.toBase64` / `Bytes.fromBase64`,
/// Converters.ts:264 and :62). A `0x`-prefixed hex string and a byte array are
/// also accepted because the older python-matter-server clients use them.
fn as_bytes(v: &Value) -> Option<Vec<u8>> {
    match v {
        Value::String(s) => match s.strip_prefix("0x").or_else(|| s.strip_prefix("0X")) {
            Some(hex) => from_hex(hex),
            None => from_base64(s),
        },
        Value::Array(items) => items
            .iter()
            .map(|i| i.as_u64().filter(|n| *n <= 255).map(|n| n as u8))
            .collect::<Option<Vec<u8>>>(),
        _ => None,
    }
}

// ---------------------------------------------------------------------------
// Decoding: TLV -> JSON
// ---------------------------------------------------------------------------

/// Decode an invoke response into an object keyed by camelCase field names.
///
/// `None` means "no named response schema" — the caller emits `null`, matching
/// `WSH:1618-1641` (status-only success → `null`).
pub fn decode_response(cluster_id: u32, command_name: &str, tlv: &Tlv) -> Option<Value> {
    let cluster = cluster(cluster_id)?;
    let cmd = cluster.command(&camelize(command_name))?;
    if cmd.response.is_empty() {
        return None;
    }
    Some(decode_struct(cluster, cmd.response, tlv))
}

/// Same, addressed by the response command id the device actually sent back.
pub fn decode_response_by_id(cluster_id: u32, response_id: u32, tlv: &Tlv) -> Option<Value> {
    let cluster = cluster(cluster_id)?;
    let cmd = cluster.command_by_response_id(response_id)?;
    if cmd.response.is_empty() {
        return None;
    }
    Some(decode_struct(cluster, cmd.response, tlv))
}

/// Decode `node_event.data`. `None` means the event is unknown — the caller
/// falls back to the tag-based encoding (PLAN.md T3).
pub fn decode_event(cluster_id: u32, event_id: u32, tlv: &Tlv) -> Option<Value> {
    let cluster = cluster(cluster_id)?;
    let event = cluster.event(event_id)?;
    Some(decode_struct(cluster, event.fields, tlv))
}

fn decode_struct(cluster: &Cluster, fields: &[Field], tlv: &Tlv) -> Value {
    let Tlv::Struct(members) = tlv else {
        return decode_untyped(tlv);
    };
    let mut out = Map::new();
    for (tag, value) in members {
        // matter.js walks the model's members and drops anything the schema does
        // not know (Converters.ts:404-417), so an unknown tag is dropped too.
        let Some(f) = fields.iter().find(|f| f.tag == *tag) else {
            continue;
        };
        let decoded = decode_value(cluster, &f.kind, value);
        // Name-based conversion emits the wire name and, when it differs, the
        // matter.js property name as well (Converters.ts:414-419).
        if let Some(prop) = f.prop {
            out.insert(prop.to_owned(), decoded.clone());
        }
        out.insert(f.wire.to_owned(), decoded);
    }
    Value::Object(out)
}

fn decode_value(cluster: &Cluster, kind: &Kind, tlv: &Tlv) -> Value {
    if matches!(tlv, Tlv::Null) {
        return Value::Null;
    }
    match kind {
        Kind::OctStr => match tlv {
            Tlv::Bytes(b) => Value::String(to_base64(b)),
            other => decode_untyped(other),
        },
        Kind::Struct(idx) => decode_struct(cluster, cluster.structs[*idx as usize].fields, tlv),
        Kind::List(inner) => match tlv {
            Tlv::Array(items) => Value::Array(
                items
                    .iter()
                    .map(|i| decode_value(cluster, inner, i))
                    .collect(),
            ),
            other => decode_untyped(other),
        },
        // Scalars, enums and bitmaps are already the wire representation.
        _ => decode_untyped(tlv),
    }
}

fn decode_untyped(tlv: &Tlv) -> Value {
    match tlv {
        Tlv::Null => Value::Null,
        Tlv::Bool(b) => Value::Bool(*b),
        Tlv::U(u) => Value::Number((*u).into()),
        Tlv::I(i) => Value::Number((*i).into()),
        Tlv::F32(f) => num(*f as f64),
        Tlv::F64(f) => num(*f),
        Tlv::Str(s) => Value::String(s.clone()),
        Tlv::Bytes(b) => Value::String(to_base64(b)),
        Tlv::Array(items) => Value::Array(items.iter().map(decode_untyped).collect()),
        // No schema, so fall back to the tag-based shape (PLAN.md §2).
        Tlv::Struct(members) => Value::Object(
            members
                .iter()
                .map(|(t, v)| (t.to_string(), decode_untyped(v)))
                .collect(),
        ),
    }
}

/// `JSON.stringify` renders NaN/Infinity as `null`; match that.
fn num(f: f64) -> Value {
    serde_json::Number::from_f64(f).map_or(Value::Null, Value::Number)
}

// ---------------------------------------------------------------------------
// base64 / hex
// ---------------------------------------------------------------------------

const B64: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

pub fn to_base64(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(bytes.len().div_ceil(3) * 4);
    for chunk in bytes.chunks(3) {
        let b = [
            chunk[0],
            *chunk.get(1).unwrap_or(&0),
            *chunk.get(2).unwrap_or(&0),
        ];
        let n = u32::from(b[0]) << 16 | u32::from(b[1]) << 8 | u32::from(b[2]);
        out.push(B64[(n >> 18) as usize & 63] as char);
        out.push(B64[(n >> 12) as usize & 63] as char);
        out.push(if chunk.len() > 1 {
            B64[(n >> 6) as usize & 63] as char
        } else {
            '='
        });
        out.push(if chunk.len() > 2 {
            B64[n as usize & 63] as char
        } else {
            '='
        });
    }
    out
}

pub fn from_base64(s: &str) -> Option<Vec<u8>> {
    let mut acc = 0u32;
    let mut bits = 0u32;
    let mut out = Vec::with_capacity(s.len() / 4 * 3);
    for c in s.bytes() {
        if c == b'=' || c.is_ascii_whitespace() {
            continue;
        }
        let v = B64.iter().position(|&b| b == c)? as u32;
        acc = acc << 6 | v;
        bits += 6;
        if bits >= 8 {
            bits -= 8;
            out.push((acc >> bits) as u8);
        }
    }
    Some(out)
}

fn from_hex(s: &str) -> Option<Vec<u8>> {
    if !s.len().is_multiple_of(2) {
        return None;
    }
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).ok())
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn tags(tlv: &Tlv) -> Vec<u8> {
        match tlv {
            Tlv::Struct(m) => m.iter().map(|(t, _)| *t).collect(),
            _ => panic!("not a struct"),
        }
    }

    #[test]
    fn camelize_matches_matterjs() {
        for (input, want) in [
            ("MoveToLevel", "moveToLevel"),
            ("move_to_level", "moveToLevel"),
            ("move-to-level", "moveToLevel"),
            ("move to level", "moveToLevel"),
            ("moveToLevel", "moveToLevel"),
            ("OnOff", "onOff"),
            ("MoveToHueAndSaturation", "moveToHueAndSaturation"),
            ("PINCode", "pinCode"),
            ("PinCode", "pinCode"),
            ("groupID", "groupId"),
            ("GroupID", "groupId"),
            ("DSTOffset", "dstOffset"),
            ("NOCSRElements", "nocsrElements"),
            ("IPv4Addresses", "iPv4Addresses"),
            ("ARLRequestFlowUrl", "arlRequestFlowUrl"),
            ("colorPointRX", "colorPointRx"),
            ("100ths", "100ths"),
            ("Percent100ths", "percent100ths"),
            ("FOOBar", "fooBar"),
            ("keep$AsIs", "keep$AsIs"),
            ("", ""),
        ] {
            assert_eq!(camelize(input), want, "camelize({input:?})");
        }
        assert_eq!(camelize_with("move_to_level", true), "MoveToLevel");
    }

    #[test]
    fn level_control_move_to_level_with_on_off() {
        let payload =
            json!({"level": 128, "transitionTime": 10, "optionsMask": 0, "optionsOverride": 0});
        let (id, tlv) = encode_command(8, "moveToLevelWithOnOff", &payload).unwrap();
        assert_eq!(id, 4);
        assert_eq!(tags(&tlv), vec![0, 1, 2, 3]);
        assert_eq!(
            tlv,
            Tlv::Struct(vec![
                (0, Tlv::U(128)),
                (1, Tlv::U(10)),
                (2, Tlv::U(0)),
                (3, Tlv::U(0)),
            ])
        );
        let cmd = cluster(8).unwrap().command("moveToLevelWithOnOff").unwrap();
        let fields: Vec<_> = cmd
            .request
            .iter()
            .map(|f| (f.tag, f.prop(), f.kind, f.nullable()))
            .collect();
        assert_eq!(
            fields,
            vec![
                (0, "level", Kind::U, false),
                (1, "transitionTime", Kind::U, true),
                (2, "optionsMask", Kind::Bitmap(0), false),
                (3, "optionsOverride", Kind::Bitmap(0), false),
            ]
        );

        // Same command via the PascalCase spelling HA's older clients use.
        assert_eq!(
            encode_command(8, "MoveToLevelWithOnOff", &payload)
                .unwrap()
                .0,
            4
        );
        // transitionTime is nullable, optionsMask/Override are mandatory.
        let nullable =
            json!({"level": 1, "transitionTime": null, "optionsMask": 0, "optionsOverride": 0});
        assert_eq!(
            encode_command(8, "moveToLevelWithOnOff", &nullable)
                .unwrap()
                .1,
            Tlv::Struct(vec![
                (0, Tlv::U(1)),
                (1, Tlv::Null),
                (2, Tlv::U(0)),
                (3, Tlv::U(0))
            ])
        );
    }

    #[test]
    fn on_off_commands_take_no_fields() {
        for (name, id) in [("on", 1u32), ("off", 0), ("toggle", 2)] {
            let (got, tlv) = encode_command(6, name, &json!({})).unwrap();
            assert_eq!(got, id, "{name}");
            assert_eq!(tlv, Tlv::Struct(vec![]));
            assert_eq!(
                encode_command(6, name, &Value::Null).unwrap().1,
                Tlv::Struct(vec![])
            );
        }
        assert_eq!(cluster_name(6), Some("OnOff"));
        assert_eq!(attribute_name(6, 0), Some("onOff"));
        assert_eq!(attribute_name(6, 0xFFFD), Some("clusterRevision"));
        // eventList is global-only; no cluster in the IDL declares it.
        assert_eq!(attribute_name(6, 0xFFFA), Some("eventList"));
    }

    #[test]
    fn switch_multi_press_complete_event() {
        let tlv = Tlv::Struct(vec![(0, Tlv::U(1)), (1, Tlv::U(2))]);
        let data = decode_event(59, 6, &tlv).unwrap();
        assert_eq!(
            data,
            json!({"previousPosition": 1, "totalNumberOfPressesCounted": 2})
        );
        assert_eq!(event_name(59, 6), Some("MultiPressComplete"));
        assert_eq!(event_name(59, 1), Some("InitialPress"));
        assert_eq!(decode_event(59, 99, &tlv), None);
    }

    #[test]
    fn door_lock_pin_code_is_an_octet_string() {
        let (id, tlv) = encode_command(257, "lockDoor", &json!({"pinCode": "0x31323334"})).unwrap();
        assert_eq!(id, 0);
        assert_eq!(tlv, Tlv::Struct(vec![(0, Tlv::Bytes(b"1234".to_vec()))]));

        // The wire form matter.js actually uses is base64 (Converters.ts:264).
        let (_, b64) = encode_command(257, "lockDoor", &json!({"pinCode": "MTIzNA=="})).unwrap();
        assert_eq!(b64, tlv);
        // PINCode is optional: an omitted or null value drops the field.
        assert_eq!(
            encode_command(257, "lockDoor", &json!({})).unwrap().1,
            Tlv::Struct(vec![])
        );
        assert_eq!(
            encode_command(257, "lockDoor", &json!({"PINCode": null}))
                .unwrap()
                .1,
            Tlv::Struct(vec![])
        );
    }

    #[test]
    fn color_control_move_to_color_temperature() {
        let (id, tlv) = encode_command(
            768,
            "moveToColorTemperature",
            &json!({"colorTemperatureMireds": 370, "transitionTime": 5,
                    "optionsMask": 0, "optionsOverride": 0}),
        )
        .unwrap();
        assert_eq!(id, 10);
        assert_eq!(
            tlv,
            Tlv::Struct(vec![
                (0, Tlv::U(370)),
                (1, Tlv::U(5)),
                (2, Tlv::U(0)),
                (3, Tlv::U(0)),
            ])
        );
        // A bitmap also accepts the flag-object form (Converters.ts:22-59).
        let (_, packed) = encode_command(
            768,
            "moveToColorTemperature",
            &json!({"colorTemperatureMireds": 370, "transitionTime": 5,
                    "optionsMask": {"executeIfOff": true}, "optionsOverride": 0}),
        )
        .unwrap();
        assert_eq!(
            packed,
            Tlv::Struct(vec![
                (0, Tlv::U(370)),
                (1, Tlv::U(5)),
                (2, Tlv::U(1)),
                (3, Tlv::U(0))
            ])
        );
    }

    #[test]
    fn nested_struct_and_list() {
        let (id, tlv) = encode_command(
            98,
            "addScene",
            &json!({
                "groupID": 1, "sceneID": 2, "transitionTime": 0, "sceneName": "evening",
                "extensionFieldSetStructs": [
                    {"clusterID": 6, "attributeValueList": [{"attributeID": 0, "valueUnsigned8": 1}]},
                    {"clusterID": 8, "attributeValueList": []}
                ]
            }),
        )
        .unwrap();
        assert_eq!(id, 0);
        assert_eq!(
            tlv,
            Tlv::Struct(vec![
                (0, Tlv::U(1)),
                (1, Tlv::U(2)),
                (2, Tlv::U(0)),
                (3, Tlv::Str("evening".into())),
                (
                    4,
                    Tlv::Array(vec![
                        Tlv::Struct(vec![
                            (0, Tlv::U(6)),
                            (
                                1,
                                Tlv::Array(vec![Tlv::Struct(vec![(0, Tlv::U(0)), (1, Tlv::U(1))])])
                            ),
                        ]),
                        Tlv::Struct(vec![(0, Tlv::U(8)), (1, Tlv::Array(vec![]))]),
                    ])
                ),
            ])
        );

        // ...and the response comes back name-based.
        let resp = decode_response(
            98,
            "addScene",
            &Tlv::Struct(vec![(0, Tlv::U(0)), (1, Tlv::U(1)), (2, Tlv::U(2))]),
        )
        .unwrap();
        assert_eq!(
            resp,
            json!({"status": 0, "groupID": 1, "groupId": 1, "sceneID": 2, "sceneId": 2})
        );
        assert_eq!(response_command_id(98, "addScene"), Some(0));
        assert_eq!(
            decode_response_by_id(98, 0, &Tlv::Struct(vec![(0, Tlv::U(0))])),
            Some(json!({"status": 0}))
        );
    }

    #[test]
    fn decode_lists_and_octet_strings() {
        // GeneralDiagnostics.HardwareFaultChange: two lists of enums.
        let tlv = Tlv::Struct(vec![
            (0, Tlv::Array(vec![Tlv::U(1), Tlv::U(3)])),
            (1, Tlv::Array(vec![])),
        ]);
        assert_eq!(
            decode_event(51, 0, &tlv).unwrap(),
            json!({"current": [1, 3], "previous": []})
        );

        // Octet strings come back base64 (Converters.ts:264).
        let resp = decode_response(
            62,
            "attestationRequest",
            &Tlv::Struct(vec![
                (0, Tlv::Bytes(b"1234".to_vec())),
                (1, Tlv::Bytes(vec![])),
            ]),
        )
        .unwrap();
        assert_eq!(
            resp,
            json!({"attestationElements": "MTIzNA==", "attestationSignature": ""})
        );

        // A tag with no schema entry is dropped, as matter.js does.
        assert_eq!(
            decode_event(51, 3, &Tlv::Struct(vec![(0, Tlv::U(2)), (9, Tlv::U(7))])).unwrap(),
            json!({"bootReason": 2})
        );
    }

    #[test]
    fn status_only_command_has_no_response_schema() {
        assert_eq!(decode_response(6, "on", &Tlv::Struct(vec![])), None);
        assert_eq!(response_command_id(6, "on"), None);
    }

    #[test]
    fn errors() {
        assert_eq!(
            encode_command(6, "explode", &json!({})),
            Err(NameError::UnknownCommand {
                cluster: 6,
                command: "explode".into()
            })
        );
        assert!(matches!(
            encode_command(9999, "on", &json!({})),
            Err(NameError::UnknownCommand { .. })
        ));
        assert_eq!(
            encode_command(8, "moveToLevel", &json!({"level": 1, "nope": 2})),
            Err(NameError::UnknownField {
                field: "nope".into()
            })
        );
        assert_eq!(
            encode_command(8, "moveToLevel", &json!({"level": 1})),
            Err(NameError::MissingField {
                field: "transitionTime".into()
            })
        );
        assert!(matches!(
            encode_command(
                8,
                "moveToLevel",
                &json!({"level": "x", "transitionTime": 0,
                "optionsMask": 0, "optionsOverride": 0})
            ),
            Err(NameError::TypeMismatch { .. })
        ));
        assert_eq!(decode_response(9999, "on", &Tlv::Struct(vec![])), None);
    }

    #[test]
    fn u64_round_trip() {
        // PLAN.md §8: 64-bit ids are bare JSON numbers and must survive.
        let big = 18446744069414584320u64;
        assert_eq!(decode_untyped(&Tlv::U(big)), json!(big));
        assert_eq!(as_u64(&json!(big)), Some(big));
        // OperationalCredentials.AddNOC carries a 64-bit caseAdminSubject.
        let (id, tlv) = encode_command(
            62,
            "addNOC",
            &json!({"NOCValue": "AQID", "IPKValue": "", "caseAdminSubject": big,
                    "adminVendorId": 65521}),
        )
        .unwrap();
        assert_eq!(id, 6);
        assert_eq!(tlv_field(&tlv, 3), Some(&Tlv::U(big)), "{tlv:?}");
        assert_eq!(tlv_field(&tlv, 0), Some(&Tlv::Bytes(vec![1, 2, 3])));
        // ICACValue is optional and was omitted, so tag 1 is absent.
        assert_eq!(tlv_field(&tlv, 1), None);
    }

    fn tlv_field(tlv: &Tlv, tag: u8) -> Option<&Tlv> {
        match tlv {
            Tlv::Struct(m) => m.iter().find(|(t, _)| *t == tag).map(|(_, v)| v),
            _ => None,
        }
    }

    #[test]
    fn base64_round_trip() {
        for case in [&b""[..], b"1", b"12", b"123", b"1234", &[0u8, 255, 128][..]] {
            let encoded = to_base64(case);
            assert_eq!(from_base64(&encoded).as_deref(), Some(case), "{encoded}");
        }
        assert_eq!(to_base64(b"1234"), "MTIzNA==");
    }

    #[test]
    fn table_invariants() {
        assert!(
            CLUSTERS.windows(2).all(|w| w[0].id < w[1].id),
            "clusters sorted by id"
        );
        for c in CLUSTERS {
            assert!(
                c.attributes.windows(2).all(|w| w[0].0 < w[1].0),
                "{} attributes",
                c.name
            );
            assert!(
                c.commands.windows(2).all(|w| w[0].name < w[1].name),
                "{} commands",
                c.name
            );
            assert!(
                c.events.windows(2).all(|w| w[0].id < w[1].id),
                "{} events",
                c.name
            );
            for cmd in c.commands {
                assert_eq!(
                    camelize(cmd.name),
                    cmd.name,
                    "{}.{} not camelized",
                    c.name,
                    cmd.name
                );
                assert!(cmd.response_id.is_some() || cmd.response.is_empty());
            }
        }
    }
}
