//! Shape of the static name table in `generated.rs`.
//!
//! Everything is a `static` slice sorted on its lookup key, so resolution is a
//! binary search with no allocation and no startup cost.

/// Wire type of a command / event field.
///
/// Enums and bitmaps are plain integers on the wire: matter.js decodes them to
/// JS values and `Converters.ts` converts them straight back to numbers
/// (`convertMatterToWebSocket`, ConvKind::Bitmap → `numberValue`; enums fall
/// through as `Passthrough`). They stay distinct kinds because the *encode*
/// direction accepts a flag object for a bitmap.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Kind {
    Bool,
    U,
    I,
    F32,
    F64,
    Str,
    OctStr,
    Enum,
    /// Index into the owning cluster's `bitmaps`.
    Bitmap(u16),
    /// Index into the owning cluster's `structs`.
    Struct(u16),
    List(&'static Kind),
}

pub const NULLABLE: u8 = 1;
pub const OPTIONAL: u8 = 2;

#[derive(Debug, Clone, Copy)]
pub struct Field {
    /// TLV context tag.
    pub tag: u8,
    /// Name as it appears on the wire (`matterNameToWireField`, ws-client/src/wire-naming.ts:174).
    pub wire: &'static str,
    /// matter.js `propertyName`; `None` when identical to `wire`.
    pub prop: Option<&'static str>,
    pub kind: Kind,
    pub flags: u8,
}

impl Field {
    pub const fn n(tag: u8, wire: &'static str, kind: Kind, flags: u8) -> Self {
        Self {
            tag,
            wire,
            prop: None,
            kind,
            flags,
        }
    }

    pub const fn p(tag: u8, wire: &'static str, prop: &'static str, kind: Kind, flags: u8) -> Self {
        Self {
            tag,
            wire,
            prop: Some(prop),
            kind,
            flags,
        }
    }

    pub fn prop(&self) -> &'static str {
        match self.prop {
            Some(p) => p,
            None => self.wire,
        }
    }

    pub fn nullable(&self) -> bool {
        self.flags & NULLABLE != 0
    }

    pub fn optional(&self) -> bool {
        self.flags & OPTIONAL != 0
    }
}

#[derive(Debug, Clone, Copy)]
pub struct Struct {
    pub name: &'static str,
    /// Sorted by `tag`.
    pub fields: &'static [Field],
}

/// A bitmap member; `mask` is the raw IDL mask, so a multi-bit member packs as
/// `(value << mask.trailing_zeros()) & mask`.
#[derive(Debug, Clone, Copy)]
pub struct BitmapMember {
    pub name: &'static str,
    pub mask: u64,
}

#[derive(Debug, Clone, Copy)]
pub struct Bitmap {
    pub name: &'static str,
    pub members: &'static [BitmapMember],
}

#[derive(Debug, Clone, Copy)]
pub struct Command {
    /// camelCase, the `device_command.command_name` lookup key.
    pub name: &'static str,
    pub id: u32,
    /// Sorted by `tag`.
    pub request: &'static [Field],
    /// `None` for a status-only command (IDL `DefaultSuccess`).
    pub response_id: Option<u32>,
    /// Sorted by `tag`.
    pub response: &'static [Field],
}

#[derive(Debug, Clone, Copy)]
pub struct Event {
    pub id: u32,
    pub name: &'static str,
    /// Sorted by `tag`.
    pub fields: &'static [Field],
}

#[derive(Debug, Clone, Copy)]
pub struct Cluster {
    pub id: u32,
    pub name: &'static str,
    /// `(attribute id, name)`, sorted by id.
    pub attributes: &'static [(u32, &'static str)],
    /// Sorted by `name`.
    pub commands: &'static [Command],
    /// Sorted by `id`.
    pub events: &'static [Event],
    /// Referenced by `Kind::Struct`; only structs reachable from commands/events.
    pub structs: &'static [Struct],
    /// Referenced by `Kind::Bitmap`.
    pub bitmaps: &'static [Bitmap],
}

impl Cluster {
    pub fn attribute(&self, id: u32) -> Option<&'static str> {
        self.attributes
            .binary_search_by_key(&id, |(i, _)| *i)
            .ok()
            .map(|i| self.attributes[i].1)
    }

    /// `name` must already be camelized.
    pub fn command(&self, name: &str) -> Option<&'static Command> {
        self.commands
            .binary_search_by(|c| c.name.cmp(name))
            .ok()
            .map(|i| &self.commands[i])
    }

    pub fn command_by_id(&self, id: u32) -> Option<&'static Command> {
        self.commands.iter().find(|c| c.id == id)
    }

    /// The command whose *response* carries `id`.
    pub fn command_by_response_id(&self, id: u32) -> Option<&'static Command> {
        self.commands.iter().find(|c| c.response_id == Some(id))
    }

    pub fn event(&self, id: u32) -> Option<&'static Event> {
        self.events
            .binary_search_by_key(&id, |e| e.id)
            .ok()
            .map(|i| &self.events[i])
    }
}

/// Global attributes (Matter core spec 7.13). Present on every cluster; the IDL
/// repeats most of them per cluster but not `eventList`.
pub static GLOBAL_ATTRIBUTES: &[(u32, &str)] = &[
    (0xFFF8, "generatedCommandList"),
    (0xFFF9, "acceptedCommandList"),
    (0xFFFA, "eventList"),
    (0xFFFB, "attributeList"),
    (0xFFFC, "featureMap"),
    (0xFFFD, "clusterRevision"),
];
