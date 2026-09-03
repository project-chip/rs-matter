//! Attribute path strings: `"<endpoint>/<cluster>/<attribute>"`, decimal, wildcard-capable.
//! Mirrors `splitAttributePath` (Converters.ts:753-780) exactly: any component that is not
//! all-ASCII-digits (missing, empty, `"*"`, negative, hex, ...) is a wildcard, and so are the
//! sentinel values `0xFFFF` (endpoint) / `0xFFFFFFFF` (cluster, attribute).

use std::fmt;

/// A possibly-wildcarded attribute path, as used by `read_attribute` / subscriptions.
/// `None` in any field means wildcard.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct AttrPath {
    pub endpoint: Option<u16>,
    pub cluster: Option<u32>,
    pub attribute: Option<u32>,
}

/// A fully-resolved path with no wildcards, as reported back for a concrete value.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct ConcretePath {
    pub endpoint: u16,
    pub cluster: u32,
    pub attribute: u32,
}

impl fmt::Display for ConcretePath {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}/{}/{}", self.endpoint, self.cluster, self.attribute)
    }
}

impl From<ConcretePath> for AttrPath {
    fn from(p: ConcretePath) -> Self {
        Self {
            endpoint: Some(p.endpoint),
            cluster: Some(p.cluster),
            attribute: Some(p.attribute),
        }
    }
}

/// Parses one decimal component: all-digits -> Some(value), anything else -> wildcard (None).
/// Matches `/^\d+$/.test(component)` — note this also rejects `-1`, `0x1`, leading/trailing
/// whitespace, and floats, all of which become wildcards, same as the TS.
fn parse_component<T>(s: &str) -> Option<T>
where
    T: std::str::FromStr,
{
    if !s.is_empty() && s.bytes().all(|b| b.is_ascii_digit()) {
        s.parse::<T>().ok()
    } else {
        None
    }
}

impl AttrPath {
    /// Parses `"e/c/a"`. Fewer than 3 `/`-separated components leaves the rest wildcarded
    /// (missing token == non-numeric token in the TS: `path.split("/")` yields `undefined`
    /// for a missing slot, and `/^\d+$/.test(undefined)` is false).
    pub fn parse(path: &str) -> Self {
        let mut parts = path.split('/');
        let endpoint = parts.next().and_then(parse_component::<u16>);
        let cluster = parts.next().and_then(parse_component::<u32>);
        let attribute = parts.next().and_then(parse_component::<u32>);

        Self {
            endpoint: endpoint.filter(|&e| e != 0xFFFF),
            cluster: cluster.filter(|&c| c != 0xFFFF_FFFF),
            attribute: attribute.filter(|&a| a != 0xFFFF_FFFF),
        }
    }

    pub fn is_wildcard(&self) -> bool {
        self.endpoint.is_none() || self.cluster.is_none() || self.attribute.is_none()
    }

    pub fn as_concrete(&self) -> Option<ConcretePath> {
        Some(ConcretePath {
            endpoint: self.endpoint?,
            cluster: self.cluster?,
            attribute: self.attribute?,
        })
    }

    pub fn matches(&self, p: &ConcretePath) -> bool {
        self.endpoint.is_none_or(|e| e == p.endpoint)
            && self.cluster.is_none_or(|c| c == p.cluster)
            && self.attribute.is_none_or(|a| a == p.attribute)
    }
}

impl fmt::Display for AttrPath {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let e = self
            .endpoint
            .map(|v| v.to_string())
            .unwrap_or_else(|| "*".into());
        let c = self
            .cluster
            .map(|v| v.to_string())
            .unwrap_or_else(|| "*".into());
        let a = self
            .attribute
            .map(|v| v.to_string())
            .unwrap_or_else(|| "*".into());
        write!(f, "{e}/{c}/{a}")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_concrete_path() {
        let p = AttrPath::parse("1/6/0");
        assert_eq!(
            p,
            AttrPath {
                endpoint: Some(1),
                cluster: Some(6),
                attribute: Some(0)
            }
        );
        assert_eq!(p.to_string(), "1/6/0");
    }

    #[test]
    fn star_and_missing_and_garbage_are_wildcards() {
        for path in ["*/6/0", "1/*/0", "1/6/*", "//", "1/6", "1", ""] {
            let p = AttrPath::parse(path);
            assert!(
                p.endpoint.is_none() || p.cluster.is_none() || p.attribute.is_none(),
                "expected at least one wildcard for {path:?}, got {p:?}"
            );
        }
        // fully wildcard forms
        assert_eq!(AttrPath::parse("*/*/*"), AttrPath::default());
        assert_eq!(AttrPath::parse(""), AttrPath::default());
    }

    #[test]
    fn negative_and_hex_and_float_components_are_wildcards() {
        let p = AttrPath::parse("-1/0x6/1.0");
        assert_eq!(p, AttrPath::default());
    }

    #[test]
    fn sentinels_are_wildcards() {
        assert_eq!(AttrPath::parse("65535/6/0").endpoint, None); // 0xFFFF
        assert_eq!(AttrPath::parse("1/4294967295/0").cluster, None); // 0xFFFFFFFF
        assert_eq!(AttrPath::parse("1/6/4294967295").attribute, None); // 0xFFFFFFFF
    }

    #[test]
    fn extra_components_ignored() {
        // split("/") on "1/6/0/7" -> ["1","6","0","7"]; only the first 3 are read.
        let p = AttrPath::parse("1/6/0/7");
        assert_eq!(
            p.as_concrete().unwrap(),
            ConcretePath {
                endpoint: 1,
                cluster: 6,
                attribute: 0
            }
        );
    }

    #[test]
    fn display_wildcard() {
        assert_eq!(AttrPath::default().to_string(), "*/*/*");
    }
}
