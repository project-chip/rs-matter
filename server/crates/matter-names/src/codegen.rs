//! Generator for `generated.rs`: parses the CSA `.matter` IDL and emits the
//! static name table.
//!
//! It lives in this crate rather than in `xtask` so the drift test can run the
//! generator in-memory and compare against the checked-in file. It is pure std
//! and reads the IDL at runtime, so nothing of it ends up in a server binary
//! beyond a few kilobytes of unreachable code.
//!
//! `rs-matter-codegen`'s own parser is not reusable: `lib.rs` declares
//! `mod idl;` privately, so `idl::parser::Idl` is unreachable from outside the
//! crate (and its pinned IDL is 1.6.0.0, not the 1.5.1.0 we target).

use std::collections::BTreeMap;
use std::fmt::Write as _;
use std::path::PathBuf;

/// IDL revision the checked-in table is generated from (PLAN.md T3).
pub const IDL_RELATIVE_PATH: &str =
    "rs-matter/rs-matter-codegen/src/idl/parser/controller-clusters-V1.5.1.0.matter";

/// This crate's directory, with symlinks resolved so a build from a linked
/// workspace still finds the repository above it.
fn manifest_dir() -> PathBuf {
    let raw = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    std::fs::canonicalize(&raw).unwrap_or(raw)
}

/// Absolute path of the IDL inside this repository checkout.
pub fn idl_path() -> PathBuf {
    // <repo>/server/crates/matter-names -> <repo>
    manifest_dir().join("../../..").join(IDL_RELATIVE_PATH)
}

/// Path of the checked-in `generated.rs`.
pub fn generated_path() -> PathBuf {
    manifest_dir().join("src/generated.rs")
}

// ---------------------------------------------------------------------------
// Lexer
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, PartialEq)]
enum Tok {
    Ident(String),
    Num(u64),
    Punct(char),
    Str,
}

fn lex(src: &str) -> Result<Vec<Tok>, String> {
    let b: Vec<char> = src.chars().collect();
    let mut out = Vec::new();
    let mut i = 0;
    while i < b.len() {
        let c = b[i];
        if c.is_whitespace() {
            i += 1;
        } else if c == '/' && b.get(i + 1) == Some(&'/') {
            while i < b.len() && b[i] != '\n' {
                i += 1;
            }
        } else if c == '/' && b.get(i + 1) == Some(&'*') {
            i += 2;
            while i + 1 < b.len() && !(b[i] == '*' && b[i + 1] == '/') {
                i += 1;
            }
            i += 2;
        } else if c == '"' {
            i += 1;
            while i < b.len() && b[i] != '"' {
                i += 1;
            }
            i += 1;
            out.push(Tok::Str);
        } else if c.is_ascii_alphabetic() || c == '_' {
            let start = i;
            while i < b.len() && (b[i].is_ascii_alphanumeric() || b[i] == '_') {
                i += 1;
            }
            out.push(Tok::Ident(b[start..i].iter().collect()));
        } else if c.is_ascii_digit() {
            let start = i;
            if c == '0' && matches!(b.get(i + 1), Some('x') | Some('X')) {
                i += 2;
                while i < b.len() && b[i].is_ascii_hexdigit() {
                    i += 1;
                }
                let s: String = b[start + 2..i].iter().collect();
                out.push(Tok::Num(
                    u64::from_str_radix(&s, 16).map_err(|e| format!("bad hex {s:?}: {e}"))?,
                ));
            } else {
                while i < b.len() && b[i].is_ascii_digit() {
                    i += 1;
                }
                let s: String = b[start..i].iter().collect();
                out.push(Tok::Num(
                    s.parse().map_err(|e| format!("bad int {s:?}: {e}"))?,
                ));
            }
        } else {
            out.push(Tok::Punct(c));
            i += 1;
        }
    }
    Ok(out)
}

// ---------------------------------------------------------------------------
// AST
// ---------------------------------------------------------------------------

#[derive(Debug, Clone)]
struct RawField {
    tag: u8,
    name: String,
    ty: String,
    list: bool,
    optional: bool,
    nullable: bool,
}

#[derive(Debug, Clone, Default)]
struct RawStruct {
    fields: Vec<RawField>,
}

#[derive(Debug, Clone)]
struct RawEvent {
    id: u32,
    name: String,
    fields: Vec<RawField>,
}

#[derive(Debug, Clone)]
struct RawCommand {
    name: String,
    id: u32,
    request: Option<String>,
    response: String,
}

#[derive(Debug, Clone)]
struct RawBitmap {
    members: Vec<(String, u64)>,
}

#[derive(Debug, Default)]
struct Scope {
    structs: BTreeMap<String, RawStruct>,
    /// Response struct name -> response command id.
    response_ids: BTreeMap<String, u32>,
    bitmaps: BTreeMap<String, RawBitmap>,
    enums: Vec<String>,
}

#[derive(Debug)]
struct RawCluster {
    id: u32,
    name: String,
    attributes: Vec<(u32, String)>,
    commands: Vec<RawCommand>,
    events: Vec<RawEvent>,
    scope: Scope,
}

const STRUCTURAL: &[&str] = &[
    "struct",
    "enum",
    "bitmap",
    "attribute",
    "event",
    "command",
    "revision",
    "cluster",
];

struct Parser {
    t: Vec<Tok>,
    i: usize,
}

impl Parser {
    fn peek(&self) -> Option<&Tok> {
        self.t.get(self.i)
    }

    fn next(&mut self) -> Option<Tok> {
        let t = self.t.get(self.i).cloned();
        self.i += 1;
        t
    }

    fn is_punct(&self, c: char) -> bool {
        matches!(self.peek(), Some(Tok::Punct(p)) if *p == c)
    }

    fn eat_punct(&mut self, c: char) -> Result<(), String> {
        match self.next() {
            Some(Tok::Punct(p)) if p == c => Ok(()),
            other => Err(format!("expected {c:?}, got {other:?} at token {}", self.i)),
        }
    }

    fn ident(&mut self) -> Result<String, String> {
        match self.next() {
            Some(Tok::Ident(s)) => Ok(s),
            other => Err(format!(
                "expected identifier, got {other:?} at token {}",
                self.i
            )),
        }
    }

    fn num(&mut self) -> Result<u64, String> {
        match self.next() {
            Some(Tok::Num(n)) => Ok(n),
            other => Err(format!(
                "expected number, got {other:?} at token {}",
                self.i
            )),
        }
    }

    fn skip_group(&mut self, open: char, close: char) -> Result<(), String> {
        self.eat_punct(open)?;
        let mut depth = 1;
        while depth > 0 {
            match self.next() {
                Some(Tok::Punct(p)) if p == open => depth += 1,
                Some(Tok::Punct(p)) if p == close => depth -= 1,
                Some(_) => {}
                None => return Err("unterminated group".into()),
            }
        }
        Ok(())
    }

    /// Consume leading modifiers (`readonly`, `request`, `timed`, `access(..)`,
    /// ...) and return them plus the structural keyword that follows.
    fn keyword(&mut self) -> Result<(Vec<String>, String), String> {
        let mut mods = Vec::new();
        loop {
            match self.peek().cloned() {
                Some(Tok::Ident(s)) if s == "access" => {
                    self.i += 1;
                    self.skip_group('(', ')')?;
                }
                Some(Tok::Ident(s)) if STRUCTURAL.contains(&s.as_str()) => {
                    self.i += 1;
                    return Ok((mods, s));
                }
                Some(Tok::Ident(s)) => {
                    self.i += 1;
                    mods.push(s);
                }
                other => return Err(format!("expected a declaration, got {other:?}")),
            }
        }
    }

    fn fields(&mut self) -> Result<Vec<RawField>, String> {
        self.eat_punct('{')?;
        let mut out = Vec::new();
        loop {
            if self.is_punct('}') {
                self.i += 1;
                break;
            }
            let mut optional = false;
            let mut nullable = false;
            let mut list = false;
            let ty = loop {
                let id = self.ident()?;
                match id.as_str() {
                    "optional" => optional = true,
                    "nullable" => nullable = true,
                    "fabric_sensitive" => {}
                    _ => break id,
                }
            };
            if self.is_punct('<') {
                self.skip_group('<', '>')?;
            }
            if self.is_punct('[') {
                self.skip_group('[', ']')?;
                list = true;
            }
            let name = self.ident()?;
            if self.is_punct('[') {
                self.skip_group('[', ']')?;
                list = true;
            }
            self.eat_punct('=')?;
            let tag = self.num()?;
            if self.is_punct('[') {
                self.skip_group('[', ']')?;
            }
            self.eat_punct(';')?;
            let tag = u8::try_from(tag).map_err(|_| format!("field tag {tag} out of range"))?;
            out.push(RawField {
                tag,
                name,
                ty,
                list,
                optional,
                nullable,
            });
        }
        out.sort_by_key(|f| f.tag);
        Ok(out)
    }

    /// `kName = <value> [anno];` members, returning name/value pairs.
    fn members(&mut self) -> Result<Vec<(String, u64)>, String> {
        self.eat_punct('{')?;
        let mut out = Vec::new();
        loop {
            if self.is_punct('}') {
                self.i += 1;
                break;
            }
            let name = self.ident()?;
            self.eat_punct('=')?;
            let value = self.num()?;
            if self.is_punct('[') {
                self.skip_group('[', ']')?;
            }
            self.eat_punct(';')?;
            out.push((name, value));
        }
        Ok(out)
    }

    fn decl(&mut self, kw: &str, mods: &[String], scope: &mut Scope) -> Result<(), String> {
        match kw {
            "revision" => {
                self.num()?;
                self.eat_punct(';')?;
            }
            "struct" => {
                let name = self.ident()?;
                if self.is_punct('=') {
                    self.i += 1;
                    let id = self.num()? as u32;
                    scope.response_ids.insert(name.clone(), id);
                }
                let fields = self.fields()?;
                scope.structs.insert(name, RawStruct { fields });
                let _ = mods;
            }
            "enum" => {
                let name = self.ident()?;
                self.eat_punct(':')?;
                self.ident()?;
                self.members()?;
                scope.enums.push(name);
            }
            "bitmap" => {
                let name = self.ident()?;
                self.eat_punct(':')?;
                self.ident()?;
                let members = self.members()?;
                scope.bitmaps.insert(name, RawBitmap { members });
            }
            other => return Err(format!("unexpected declaration {other:?}")),
        }
        Ok(())
    }

    fn cluster(&mut self) -> Result<RawCluster, String> {
        let name = self.ident()?;
        self.eat_punct('=')?;
        let id = self.num()? as u32;
        self.eat_punct('{')?;

        let mut c = RawCluster {
            id,
            name,
            attributes: Vec::new(),
            commands: Vec::new(),
            events: Vec::new(),
            scope: Scope::default(),
        };

        loop {
            if self.is_punct('}') {
                self.i += 1;
                break;
            }
            let (mods, kw) = self.keyword()?;
            match kw.as_str() {
                "attribute" => {
                    loop {
                        match self.peek().cloned() {
                            Some(Tok::Ident(s)) if s == "access" => {
                                self.i += 1;
                                self.skip_group('(', ')')?;
                            }
                            Some(Tok::Ident(s))
                                if matches!(
                                    s.as_str(),
                                    "optional" | "nullable" | "fabric_sensitive"
                                ) =>
                            {
                                self.i += 1;
                            }
                            _ => break,
                        }
                    }
                    self.ident()?; // type
                    if self.is_punct('<') {
                        self.skip_group('<', '>')?;
                    }
                    if self.is_punct('[') {
                        self.skip_group('[', ']')?;
                    }
                    let name = self.ident()?;
                    if self.is_punct('[') {
                        self.skip_group('[', ']')?;
                    }
                    self.eat_punct('=')?;
                    let id = self.num()? as u32;
                    self.eat_punct(';')?;
                    c.attributes.push((id, name));
                }
                "event" => {
                    if matches!(self.peek(), Some(Tok::Ident(s)) if s == "access") {
                        self.i += 1;
                        self.skip_group('(', ')')?;
                    }
                    let name = self.ident()?;
                    self.eat_punct('=')?;
                    let id = self.num()? as u32;
                    let fields = self.fields()?;
                    c.events.push(RawEvent { id, name, fields });
                }
                "command" => {
                    if matches!(self.peek(), Some(Tok::Ident(s)) if s == "access") {
                        self.i += 1;
                        self.skip_group('(', ')')?;
                    }
                    let name = self.ident()?;
                    self.eat_punct('(')?;
                    let request = if self.is_punct(')') {
                        None
                    } else {
                        Some(self.ident()?)
                    };
                    self.eat_punct(')')?;
                    self.eat_punct(':')?;
                    let response = self.ident()?;
                    self.eat_punct('=')?;
                    let id = self.num()? as u32;
                    self.eat_punct(';')?;
                    c.commands.push(RawCommand {
                        name,
                        id,
                        request,
                        response,
                    });
                }
                other => self.decl(other, &mods, &mut c.scope)?,
            }
        }
        c.attributes.sort_by_key(|(id, _)| *id);
        c.attributes.dedup_by_key(|(id, _)| *id);
        c.events.sort_by_key(|e| e.id);
        Ok(c)
    }
}

fn parse(src: &str) -> Result<(Vec<RawCluster>, Scope), String> {
    let mut p = Parser { t: lex(src)?, i: 0 };
    let mut clusters = Vec::new();
    let mut globals = Scope::default();
    while p.peek().is_some() {
        let (mods, kw) = p.keyword()?;
        if kw == "cluster" {
            clusters.push(p.cluster()?);
        } else {
            p.decl(&kw, &mods, &mut globals)?;
        }
    }
    clusters.sort_by_key(|c| c.id);
    Ok((clusters, globals))
}

// ---------------------------------------------------------------------------
// Type resolution
// ---------------------------------------------------------------------------

/// Base IDL types. Enums/bitmaps/semantic ints are all plain integers on the
/// wire; the distinction only affects how we coerce the JSON side.
fn base_kind(ty: &str) -> Option<&'static str> {
    let t = ty.to_ascii_lowercase();
    Some(match t.as_str() {
        "boolean" => "Bool",
        "single" => "F32",
        "double" => "F64",
        "char_string" | "long_char_string" => "Str",
        "octet_string" | "long_octet_string" | "ipadr" | "ipv4adr" | "ipv6adr" | "ipv6pre"
        | "hwadr" => "OctStr",
        "enum8" | "enum16" | "enum32" | "status" | "priority" => "Enum",
        // Anonymous bitmaps have no member list, so they behave as integers.
        "bitmap8" | "bitmap16" | "bitmap32" | "bitmap64" => "U",
        "int8u" | "int16u" | "int24u" | "int32u" | "int40u" | "int48u" | "int56u" | "int64u"
        | "percent" | "percent100ths" | "epoch_s" | "epoch_us" | "elapsed_s" | "systime_ms"
        | "systime_us" | "posix_ms" | "utc" | "tod" | "date" | "node_id" | "group_id"
        | "endpoint_no" | "vendor_id" | "cluster_id" | "attrib_id" | "field_id" | "command_id"
        | "event_id" | "action_id" | "trans_id" | "devtype_id" | "fabric_id" | "fabric_idx"
        | "entry_idx" | "data_ver" | "tag" | "namespace" | "counter" => "U",
        "int8s" | "int16s" | "int24s" | "int32s" | "int40s" | "int48s" | "int56s" | "int64s"
        | "temperature" | "power_mw" | "power_mva" | "power_mvar" | "energy_mwh"
        | "energy_mvah" | "energy_mvarh" | "amperage_ma" | "voltage_mv" | "money" => "I",
        _ => return None,
    })
}

/// Per-cluster emission state: the struct/bitmap tables reachable from the
/// cluster's commands and events, in discovery order.
struct Tables<'a> {
    cluster: &'a RawCluster,
    globals: &'a Scope,
    structs: Vec<(String, RawStruct)>,
    struct_index: BTreeMap<String, u16>,
    bitmaps: Vec<(String, RawBitmap)>,
    bitmap_index: BTreeMap<String, u16>,
}

impl<'a> Tables<'a> {
    fn new(cluster: &'a RawCluster, globals: &'a Scope) -> Self {
        Self {
            cluster,
            globals,
            structs: Vec::new(),
            struct_index: BTreeMap::new(),
            bitmaps: Vec::new(),
            bitmap_index: BTreeMap::new(),
        }
    }

    fn find_struct(&self, name: &str) -> Option<&RawStruct> {
        self.cluster
            .scope
            .structs
            .get(name)
            .or_else(|| self.globals.structs.get(name))
    }

    fn find_bitmap(&self, name: &str) -> Option<&RawBitmap> {
        self.cluster
            .scope
            .bitmaps
            .get(name)
            .or_else(|| self.globals.bitmaps.get(name))
    }

    fn is_enum(&self, name: &str) -> bool {
        self.cluster.scope.enums.iter().any(|e| e == name)
            || self.globals.enums.iter().any(|e| e == name)
    }

    fn kind(&mut self, f: &RawField) -> Result<String, String> {
        let scalar = self.scalar_kind(&f.ty)?;
        Ok(if f.list {
            format!("K::List(&{scalar})")
        } else {
            scalar
        })
    }

    fn scalar_kind(&mut self, ty: &str) -> Result<String, String> {
        if let Some(base) = base_kind(ty) {
            return Ok(format!("K::{base}"));
        }
        if self.find_struct(ty).is_some() {
            return Ok(format!("K::Struct({})", self.intern_struct(ty)?));
        }
        if self.find_bitmap(ty).is_some() {
            return Ok(format!("K::Bitmap({})", self.intern_bitmap(ty)));
        }
        if self.is_enum(ty) {
            return Ok("K::Enum".into());
        }
        Err(format!(
            "unresolved type {ty:?} in cluster {}",
            self.cluster.name
        ))
    }

    fn intern_struct(&mut self, name: &str) -> Result<u16, String> {
        if let Some(i) = self.struct_index.get(name) {
            return Ok(*i);
        }
        let s = self.find_struct(name).expect("checked by caller").clone();
        let idx = u16::try_from(self.structs.len()).map_err(|_| "too many structs".to_string())?;
        self.struct_index.insert(name.to_owned(), idx);
        self.structs.push((name.to_owned(), s.clone()));
        // Resolve nested types after reserving the index so a self-reference
        // terminates.
        for f in &s.fields {
            self.kind(f)?;
        }
        Ok(idx)
    }

    fn intern_bitmap(&mut self, name: &str) -> u16 {
        if let Some(i) = self.bitmap_index.get(name) {
            return *i;
        }
        let b = self.find_bitmap(name).expect("checked by caller").clone();
        let idx = self.bitmaps.len() as u16;
        self.bitmap_index.insert(name.to_owned(), idx);
        self.bitmaps.push((name.to_owned(), b));
        idx
    }
}

/// Wire field name -> matter.js `propertyName`, for the handful of names where
/// `camelize(wireName) != camelize(modelName)`.
///
/// The IDL field name *is* the chip/wire name (verified against every entry of
/// `FIELD_NAME_OVERRIDES`, ws-client/src/wire-naming.ts:88), and matter.js's
/// `propertyName` is `camelize(modelName)` (model/src/models/Model.ts:88). The
/// two agree everywhere except where matter.js spells the model name as one
/// word — only `Watermark`/`waterMark` (wire-naming.ts:120) reaches a command
/// or event field.
const PROP_OVERRIDES: &[(&str, &str)] = &[("waterMark", "watermark")];

fn prop_name(wire: &str) -> String {
    for (w, p) in PROP_OVERRIDES {
        if *w == wire {
            return (*p).to_owned();
        }
    }
    crate::camelize(wire)
}

// ---------------------------------------------------------------------------
// Emitter
// ---------------------------------------------------------------------------

fn emit_field(out: &mut String, f: &RawField, kind: &str) {
    let mut flags = String::new();
    if f.nullable {
        flags.push_str("NULLABLE");
    }
    if f.optional {
        if !flags.is_empty() {
            flags.push('|');
        }
        flags.push_str("OPTIONAL");
    }
    if flags.is_empty() {
        flags.push('0');
    }
    let prop = prop_name(&f.name);
    if prop == f.name {
        let _ = write!(out, "F::n({},{:?},{},{}),", f.tag, f.name, kind, flags);
    } else {
        let _ = write!(
            out,
            "F::p({},{:?},{:?},{},{}),",
            f.tag, f.name, prop, kind, flags
        );
    }
}

fn emit_fields(out: &mut String, tables: &mut Tables, fields: &[RawField]) -> Result<(), String> {
    out.push_str("&[");
    for f in fields {
        let kind = tables.kind(f)?;
        emit_field(out, f, &kind);
    }
    out.push(']');
    Ok(())
}

/// Parse `idl` and render the contents of `generated.rs`.
pub fn generate(idl: &str) -> Result<String, String> {
    let (clusters, globals) = parse(idl)?;

    let mut body = String::new();
    for c in &clusters {
        let mut tables = Tables::new(c, &globals);

        // Commands first: a struct index must be stable, and commands are the
        // hot path.
        let mut commands: Vec<(String, &RawCommand)> = c
            .commands
            .iter()
            .map(|cmd| (crate::camelize(&cmd.name), cmd))
            .collect();
        commands.sort_by(|a, b| a.0.cmp(&b.0));
        commands.dedup_by(|a, b| a.0 == b.0);

        let mut cmd_src = String::new();
        for (name, cmd) in &commands {
            let request = match &cmd.request {
                Some(r) => tables
                    .find_struct(r)
                    .ok_or_else(|| format!("missing request struct {r:?}"))?
                    .fields
                    .clone(),
                None => Vec::new(),
            };
            // `DefaultSuccess` is the IDL's status-only sentinel; anything else
            // must be a declared `response struct` or we would silently drop the
            // response fields.
            let response_id = c.scope.response_ids.get(&cmd.response).copied();
            let response = match response_id {
                Some(_) => tables
                    .find_struct(&cmd.response)
                    .ok_or_else(|| format!("missing response struct {:?}", cmd.response))?
                    .fields
                    .clone(),
                None if cmd.response == "DefaultSuccess" => Vec::new(),
                None => {
                    return Err(format!(
                        "{}.{} returns undeclared {:?}",
                        c.name, cmd.name, cmd.response
                    ))
                }
            };
            let _ = write!(cmd_src, "Command{{name:{name:?},id:{},request:", cmd.id);
            emit_fields(&mut cmd_src, &mut tables, &request)?;
            let _ = write!(
                cmd_src,
                ",response_id:{},response:",
                match response_id {
                    Some(id) => format!("Some({id})"),
                    None => "None".into(),
                }
            );
            emit_fields(&mut cmd_src, &mut tables, &response)?;
            cmd_src.push_str("},");
        }

        let mut evt_src = String::new();
        for e in &c.events {
            let _ = write!(evt_src, "Event{{id:{},name:{:?},fields:", e.id, e.name);
            emit_fields(&mut evt_src, &mut tables, &e.fields)?;
            evt_src.push_str("},");
        }

        // Interning above grows `tables.structs` while we walk it, so index.
        let mut struct_src = String::new();
        let mut i = 0;
        while i < tables.structs.len() {
            let (name, s) = tables.structs[i].clone();
            let _ = write!(struct_src, "Struct{{name:{name:?},fields:");
            emit_fields(&mut struct_src, &mut tables, &s.fields)?;
            struct_src.push_str("},");
            i += 1;
        }

        let mut bitmap_src = String::new();
        for (name, b) in &tables.bitmaps {
            let _ = write!(bitmap_src, "Bitmap{{name:{name:?},members:&[");
            for (member, mask) in &b.members {
                let member = crate::camelize(member.strip_prefix('k').unwrap_or(member));
                let _ = write!(bitmap_src, "M{{name:{member:?},mask:{mask}}},");
            }
            bitmap_src.push_str("]},");
        }

        let _ = write!(body, "Cluster{{id:{},name:{:?},attributes:&[", c.id, c.name);
        for (id, name) in &c.attributes {
            let _ = write!(body, "({id},{name:?}),");
        }
        let _ = write!(body, "],\ncommands:&[{cmd_src}],\nevents:&[{evt_src}],\n");
        let _ = write!(
            body,
            "structs:&[{struct_src}],\nbitmaps:&[{bitmap_src}]}},\n"
        );
    }

    Ok(format!(
        "// @generated by `cargo run -p xtask -- gen-names`. DO NOT EDIT.\n\
         //\n\
         // Source: {IDL_RELATIVE_PATH}\n\
         // Pulled in with `include!` so `cargo fmt` leaves the layout alone.\n\
         \n\
         use crate::table::{{Bitmap, BitmapMember as M, Cluster, Command, Event, Field as F, Kind as K, Struct, NULLABLE, OPTIONAL}};\n\
         \n\
         /// All clusters, sorted by id.\n\
         pub static CLUSTERS: &[Cluster] = &[\n{body}];\n"
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn generated_rs_is_up_to_date() {
        let idl = std::fs::read_to_string(idl_path())
            .unwrap_or_else(|e| panic!("cannot read {}: {e}", idl_path().display()));
        let fresh = generate(&idl).expect("generator failed");
        let checked_in = std::fs::read_to_string(generated_path()).expect("generated.rs missing");
        assert!(
            fresh == checked_in,
            "src/generated.rs is stale ({} vs {} bytes); run `cargo run -p xtask -- gen-names`",
            checked_in.len(),
            fresh.len()
        );
    }
}
