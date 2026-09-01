/*
 *
 *    Copyright (c) 2026 Project CHIP Authors
 *
 *    Licensed under the Apache License, Version 2.0 (the "License");
 *    you may not use this file except in compliance with the License.
 *    You may obtain a copy of the License at
 *
 *        http://www.apache.org/licenses/LICENSE-2.0
 *
 *    Unless required by applicable law or agreed to in writing, software
 *    distributed under the License is distributed on an "AS IS" BASIS,
 *    WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *    See the License for the specific language governing permissions and
 *    limitations under the License.
 */

//! Fill in the CSA master PICS templates from a device's own data model.
//!
//! Consumes the JSON emitted by `Matter::write_pics_json` and rewrites the `<support>`
//! element of every PICS item it can answer mechanically.
//!
//! The templates are CSA member material and are **never** committed to this
//! repository - they are always supplied on the command line.
//!
//! Two properties matter for trust in the output:
//! - The templates ship *pre-answered*, overwhelmingly `true`. So every
//!   derivable item is **overwritten**, never merely filled in when blank.
//! - Everything the tool cannot derive is left exactly as the template had it
//!   and listed in the report, so what remains for a human is explicit rather
//!   than silently inherited.

use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::io::{IsTerminal, Read, Write};
use std::path::Path;

use anyhow::{anyhow, Context};
use log::{info, warn};

/// PICS root (as used in item numbers) to Matter cluster ID.
///
/// The master templates leave `<clusterId>` empty in every file, so the cluster
/// a template describes can only be recovered from the prefix of its item
/// numbers.
///
/// Derived mechanically for the whole Matter 1.6 set: every `<name>` in the
/// master PICS templates was matched against the `<name>`/`<code>` pairs in the
/// SDK's ZAP cluster definitions. 39 of the 41 entries that had previously been
/// written by hand came back identical, which is the cross-check that this
/// table is right.
///
/// Deliberately absent, because they are not clusters and mapping them would
/// yield confidently wrong answers:
///
/// * `MCORE` - the general (non-cluster) PICS in `Base.xml`;
/// * `PLAT` - platform certification declarations;
/// * `ICDB` - ICD *behaviour*, covered by the `ICDM` cluster;
/// * `APPDEVICE` - a device-type claim;
/// * `MC` - "casting video player", a device type whose sub-items are manual.
const PICS_ROOTS: &[(&str, u32)] = &[
    ("I", 0x0003),
    ("G", 0x0004),
    ("OO", 0x0006),
    ("LVL", 0x0008),
    ("DESC", 0x001D),
    ("BIND", 0x001E),
    ("ACL", 0x001F),
    ("ACT", 0x0025),
    ("BINFO", 0x0028),
    ("OTAP", 0x0029),
    ("OTAR", 0x002A),
    ("LCFG", 0x002B),
    ("LTIME", 0x002C),
    ("LUNIT", 0x002D),
    ("PSCFG", 0x002E),
    ("PS", 0x002F),
    ("CGEN", 0x0030),
    ("CNET", 0x0031),
    ("DLOG", 0x0032),
    ("DGGEN", 0x0033),
    ("DGSW", 0x0034),
    ("DGTHREAD", 0x0035),
    ("DGWIFI", 0x0036),
    ("DGETH", 0x0037),
    ("TIMESYNC", 0x0038),
    ("BRBINFO", 0x0039),
    ("SWTCH", 0x003B),
    ("CADMIN", 0x003C),
    ("OPCREDS", 0x003E),
    ("GRPKEY", 0x003F),
    ("FLABEL", 0x0040),
    ("ULABEL", 0x0041),
    ("BOOL", 0x0045),
    ("ICDM", 0x0046),
    ("OVENOPSTATE", 0x0048),
    ("OTCCM", 0x0049),
    ("DRYERCTRL", 0x004A),
    ("MOD", 0x0050),
    ("LWM", 0x0051),
    ("TCCM", 0x0052),
    ("WASHERCTRL", 0x0053),
    ("RVCRUNM", 0x0054),
    ("RVCCLEANM", 0x0055),
    ("TCTL", 0x0056),
    ("REFALM", 0x0057),
    ("DISHM", 0x0059),
    ("AIRQUAL", 0x005B),
    ("SMOKECO", 0x005C),
    ("DISHALM", 0x005D),
    ("MWOM", 0x005E),
    ("MWOCTRL", 0x005F),
    ("OPSTATE", 0x0060),
    ("RVCOPSTATE", 0x0061),
    ("S", 0x0062),
    ("GC", 0x0065),
    ("HEPAFREMON", 0x0071),
    ("ACFREMON", 0x0072),
    ("BOOLCFG", 0x0080),
    ("VALCC", 0x0081),
    ("EPM", 0x0090),
    ("EEM", 0x0091),
    ("EWATERHTR", 0x0094),
    ("SEPR", 0x0095),
    ("MESS", 0x0097),
    ("DEM", 0x0098),
    ("EEVSE", 0x0099),
    ("EPREF", 0x009B),
    ("PWRTL", 0x009C),
    ("EEVSEM", 0x009D),
    ("WHM", 0x009E),
    ("DEMM", 0x009F),
    ("EGC", 0x00A0),
    ("DRLK", 0x0101),
    ("WNCV", 0x0102),
    ("CLCTRL", 0x0104),
    ("CLDIM", 0x0105),
    ("SEAR", 0x0150),
    ("PCC", 0x0200),
    ("TSTAT", 0x0201),
    ("FAN", 0x0202),
    ("TSUIC", 0x0204),
    ("CC", 0x0300),
    ("ILL", 0x0400),
    ("TMP", 0x0402),
    ("PRS", 0x0403),
    ("FLW", 0x0404),
    ("RH", 0x0405),
    ("OCC", 0x0406),
    ("CMOCONC", 0x040C),
    ("CDOCONC", 0x040D),
    ("NDOCONC", 0x0413),
    ("OZCONC", 0x0415),
    ("PMICONC", 0x042A),
    ("FLDCONC", 0x042B),
    ("PMHCONC", 0x042C),
    ("PMKCONC", 0x042D),
    ("TVOCCONC", 0x042E),
    ("RNCONC", 0x042F),
    ("SOIL", 0x0430),
    ("WIFINM", 0x0451),
    ("TBRM", 0x0452),
    ("THNETDIR", 0x0453),
    ("WAKEONLAN", 0x0503),
    ("CHANNEL", 0x0504),
    ("TGTNAV", 0x0505),
    ("MEDIAPLAYBACK", 0x0506),
    ("MEDIAINPUT", 0x0507),
    ("LOWPOWER", 0x0508),
    ("KEYPADINPUT", 0x0509),
    ("CONTENTLAUNCHER", 0x050A),
    ("AUDIOOUTPUT", 0x050B),
    ("APPLAUNCHER", 0x050C),
    ("APBSC", 0x050D),
    ("ALOGIN", 0x050E),
    ("CONCON", 0x050F),
    ("APPOBSERVER", 0x0510),
    ("ZONEMGMT", 0x0550),
    ("AVSM", 0x0551),
    ("AVSUM", 0x0552),
    ("WEBRTCP", 0x0553),
    ("WEBRTCR", 0x0554),
    ("PAVST", 0x0555),
    ("CHIME", 0x0556),
    ("SETRF", 0x0700),
    ("ECOINFO", 0x0750),
    ("CCTRL", 0x0751),
    ("JFDS", 0x0752),
    ("JFADMIN", 0x0753),
    ("TLSCERT", 0x0801),
    ("TLSCLIENT", 0x0802),
    ("MTRID", 0x0B06),
    ("COMMTR", 0x0B07),
];

/// What one cluster of the device serves, flattened across endpoints.
#[derive(Default)]
struct ClusterInfo {
    feature_map: u32,
    attributes: BTreeSet<u32>,
    commands_received: BTreeSet<u32>,
    commands_generated: BTreeSet<u32>,
    events: BTreeSet<u32>,
}

/// The device's data model, as reported by `Matter::write_pics_json`.
struct NodeInfo {
    servers: BTreeMap<u32, ClusterInfo>,
    clients: BTreeSet<u32>,
    /// `(endpoint id, device types, server cluster ids)`, kept in declaration
    /// order purely so the summary reads like the device does.
    endpoints: Vec<(u16, Vec<u16>, Vec<u32>)>,
    /// What the node actually advertises, as the stack builds it. This is the
    /// only source for the `MCORE.SC.*` and `MCORE.DD.TXT_KEY_*` items: they
    /// ask which DNS-SD keys and subtypes appear, which no cluster reports.
    mdns: MdnsInfo,
}

/// The TXT keys and subtypes on each of the node's two DNS-SD services.
#[derive(Default)]
struct MdnsInfo {
    commissionable_txt: BTreeSet<String>,
    commissionable_subtypes: Vec<String>,
    operational_txt: BTreeSet<String>,
}

impl NodeInfo {
    fn parse(json: &str) -> anyhow::Result<Self> {
        let v: serde_json::Value = serde_json::from_str(json).context("malformed node JSON")?;

        let schema = v["schema"].as_u64().ok_or_else(|| anyhow!("no `schema`"))?;
        if schema != 1 {
            return Err(anyhow!(
                "node JSON schema {schema} is not supported (expected 1); \
                 rebuild the device with a matching `rs-matter`"
            ));
        }

        let mut servers: BTreeMap<u32, ClusterInfo> = BTreeMap::new();
        let mut clients = BTreeSet::new();
        let mut shape = Vec::new();

        let endpoints = v["endpoints"]
            .as_array()
            .ok_or_else(|| anyhow!("no `endpoints`"))?;

        for ep in endpoints {
            shape.push((
                ep["id"].as_u64().unwrap_or_default() as u16,
                ep["device_types"]
                    .as_array()
                    .into_iter()
                    .flatten()
                    .filter_map(|dt| dt["dtype"].as_u64().map(|v| v as u16))
                    .collect(),
                ep["clusters"]
                    .as_array()
                    .into_iter()
                    .flatten()
                    .filter_map(|c| c["id"].as_u64().map(|v| v as u32))
                    .collect(),
            ));

            for id in ep["client_clusters"].as_array().into_iter().flatten() {
                clients.insert(id.as_u64().unwrap_or_default() as u32);
            }

            for cl in ep["clusters"].as_array().into_iter().flatten() {
                let id = cl["id"]
                    .as_u64()
                    .ok_or_else(|| anyhow!("cluster without id"))? as u32;

                // A cluster may appear on several endpoints; the PICS
                // declaration is per *node*, so the union is what we want.
                let info = servers.entry(id).or_default();

                info.feature_map |= cl["feature_map"].as_u64().unwrap_or_default() as u32;

                for (key, set) in [
                    ("attributes", &mut info.attributes),
                    ("commands_received", &mut info.commands_received),
                    ("commands_generated", &mut info.commands_generated),
                    ("events", &mut info.events),
                ] {
                    for item in cl[key].as_array().into_iter().flatten() {
                        set.insert(item.as_u64().unwrap_or_default() as u32);
                    }
                }
            }
        }

        let strings = |v: &serde_json::Value| -> Vec<String> {
            v.as_array()
                .into_iter()
                .flatten()
                .filter_map(|s| s.as_str().map(str::to_string))
                .collect()
        };

        let mdns = MdnsInfo {
            // `DUMMY` is filler the stack adds so a TXT record is never empty
            // (see `transport::network::mdns`); it is not a Matter key.
            commissionable_txt: strings(&v["mdns"]["commissionable"]["txt"])
                .into_iter()
                .filter(|k| k != "DUMMY")
                .collect(),
            commissionable_subtypes: strings(&v["mdns"]["commissionable"]["subtypes"]),
            operational_txt: strings(&v["mdns"]["operational"]["txt"])
                .into_iter()
                .filter(|k| k != "DUMMY")
                .collect(),
        };

        Ok(Self {
            servers,
            clients,
            endpoints: shape,
            mdns,
        })
    }

    /// Answer a single PICS item, or `None` when it is not derivable from the
    /// data model (`MCORE.*`, `PIXIT.*`, manual `.M.` behaviours, or a cluster
    /// whose PICS root is not in [`PICS_ROOTS`]).
    fn resolve(&self, item: &str) -> Option<bool> {
        let (root, rest) = item.split_once('.')?;
        let id = PICS_ROOTS
            .iter()
            .find_map(|(name, id)| (*name == root).then_some(*id))?;

        let server = self.servers.get(&id);

        // Roles.
        match rest {
            "S" => return Some(server.is_some()),
            "C" => return Some(self.clients.contains(&id)),
            _ => {}
        }

        let (role, sub) = rest.split_once('.')?;

        // Client-side items describe what the device *initiates*.
        //
        // If the cluster is not in this node's client list at all, nothing on
        // its client surface can be supported - that much is decidable, and it
        // accounts for the bulk of the client-side questionnaire.
        //
        // When the cluster *is* a client the answer stops being derivable: the
        // data model records that the endpoint initiates for the cluster, not
        // which of its attributes the application reads or which commands it
        // invokes. Those are left to a human.
        if role == "C" {
            return (!self.clients.contains(&id)).then_some(false);
        }
        if role != "S" {
            return None;
        }

        // A cluster the node does not serve cannot support anything on its
        // server surface, so `server` being absent still answers the question -
        // it is only the *shape* of the item that has to be recognised below.

        // Attributes: `A` + 4 hex digits.
        if let Some(hex) = sub.strip_prefix('A') {
            let id = u32::from_str_radix(hex, 16).ok()?;
            return Some(server.is_some_and(|i| i.attributes.contains(&id)));
        }

        // Feature bits: `F` + 2 hex digits.
        if let Some(hex) = sub.strip_prefix('F') {
            let bit = u32::from_str_radix(hex, 16).ok()?;
            return Some(server.is_some_and(|i| i.feature_map & (1 << bit) != 0));
        }

        // Events: `E` + 2 hex digits.
        if let Some(hex) = sub.strip_prefix('E') {
            let id = u32::from_str_radix(hex, 16).ok()?;
            return Some(server.is_some_and(|i| i.events.contains(&id)));
        }

        // Commands: `C` + 2 hex digits, then `.Rsp` (received) or `.Tx` (generated).
        if let Some(rest) = sub.strip_prefix('C') {
            let (hex, dir) = rest.split_once('.')?;
            let id = u32::from_str_radix(hex, 16).ok()?;

            return match dir {
                "Rsp" => Some(server.is_some_and(|i| i.commands_received.contains(&id))),
                "Tx" => Some(server.is_some_and(|i| i.commands_generated.contains(&id))),
                _ => None,
            };
        }

        None
    }
}

/// Tally of what one run did, for the report.
#[derive(Default)]
struct Report {
    changed: usize,
    confirmed: usize,
    left: BTreeMap<String, usize>,
    /// Every answer the data model decided, for the flat `.pics` output.
    derived: BTreeMap<String, bool>,
    /// Items on a served cluster that the data model cannot answer.
    left_items: Vec<String>,
    /// PICS roots appearing in the template, used to decide whether the file is
    /// about this device at all.
    roots: BTreeSet<String>,
}

/// Rewrite every `<support>` this tool can answer, preserving the file
/// byte-for-byte otherwise.
///
/// Deliberately line-oriented rather than a real XML round-trip: the output
/// must stay diffable against the CSA original, so that what changed is
/// reviewable.
fn fill_template(
    xml: &str,
    node: &NodeInfo,
    answers: &BTreeMap<String, bool>,
    report: &mut Report,
) -> String {
    let mut out = String::with_capacity(xml.len());
    // PIXIT entries live in `<pixitItem>` and carry values rather than
    // booleans; they are never touched.
    let mut in_pics_item = false;
    let mut item: Option<String> = None;

    for line in xml.split_inclusive('\n') {
        let trimmed = line.trim();

        if trimmed.starts_with("<picsItem>") {
            in_pics_item = true;
            item = None;
        } else if trimmed.starts_with("</picsItem>") {
            in_pics_item = false;
            item = None;
        } else if trimmed.starts_with("<pixitItem>") {
            in_pics_item = false;
        }

        if in_pics_item {
            if let Some(n) = between(trimmed, "<itemNumber>", "</itemNumber>") {
                item = Some(n.to_string());
            } else if between(trimmed, "<support>", "</support>").is_some() {
                if let Some(name) = item.as_deref() {
                    report
                        .roots
                        .insert(name.split('.').next().unwrap_or(name).to_string());

                    // `answers` carries what the data model could not settle
                    // on its own - transports derived from the CNET feature
                    // map, and the operator's answers to the questions. It
                    // wins over `resolve`, which returns `None` for exactly
                    // those items.
                    if let Some(answer) = answers.get(name).copied().or_else(|| node.resolve(name))
                    {
                        let indent = &line[..line.len() - line.trim_start().len()];
                        let eol = if line.ends_with("\r\n") {
                            "\r\n"
                        } else if line.ends_with('\n') {
                            "\n"
                        } else {
                            ""
                        };

                        let replacement = format!("{indent}<support>{answer}</support>{eol}");

                        if replacement == line {
                            report.confirmed += 1;
                        } else {
                            report.changed += 1;
                        }

                        report.derived.insert(name.to_string(), answer);

                        out.push_str(&replacement);
                        continue;
                    }

                    let root = name.split('.').next().unwrap_or(name);
                    *report.left.entry(root.to_string()).or_default() += 1;
                    report.left_items.push(name.to_string());
                }
            }
        }

        out.push_str(line);
    }

    out
}

fn between<'a>(s: &'a str, open: &str, close: &str) -> Option<&'a str> {
    let rest = s.strip_prefix(open)?;
    rest.strip_suffix(close)
}

/// Parse the SDK's flat `KEY=1` PICS format.
fn parse_flat(text: &str) -> BTreeMap<String, bool> {
    text.lines()
        .filter_map(|line| {
            let line = line.split('#').next().unwrap_or("").trim();
            let (k, v) = line.split_once('=')?;
            Some((k.trim().to_string(), v.trim() == "1"))
        })
        .collect()
}

/// Emit the flat `KEY=1` form consumed by the SDK's own runners
/// (`chip-tool`'s YAML suites and `run_python_test.py`).
///
/// Derived answers come from the data model. Anything the data model cannot
/// decide is carried over verbatim from `baseline`, if one was given, into a
/// clearly separated section - so the generated file stays a superset of a
/// hand-curated one rather than silently dropping entries such as
/// `PICS_SDK_CI_ONLY`.
fn write_flat(
    path: &Path,
    node_path: &Path,
    report: &Report,
    baseline: Option<(&Path, &BTreeMap<String, bool>)>,
) -> anyhow::Result<()> {
    let mut out = String::new();

    out.push_str("# Generated by `cargo xtask pics` - do not hand-edit the derived section.\n");
    out.push_str(&format!("# Data model: {}\n", node_path.display()));

    let mut by_root: BTreeMap<&str, Vec<(&String, &bool)>> = BTreeMap::new();
    for (item, answer) in &report.derived {
        by_root
            .entry(item.split('.').next().unwrap_or(item))
            .or_default()
            .push((item, answer));
    }

    for (root, items) in &by_root {
        out.push_str(&format!("\n# ---- {root} ----\n"));
        for (item, answer) in items {
            out.push_str(&format!("{item}={}\n", if **answer { 1 } else { 0 }));
        }
    }

    // Whatever the data model could not decide.
    if !report.left_items.is_empty() {
        out.push_str("\n# ---- Not derivable from the data model ----\n");
        if let Some((path, _)) = baseline {
            out.push_str(&format!(
                "# Values below are carried over from {}.\n",
                path.display()
            ));
        } else {
            out.push_str("# No baseline given; these default to 0 and need review.\n");
        }

        let mut left = report.left_items.clone();
        left.sort();
        left.dedup();

        for item in left {
            let answer = baseline
                .and_then(|(_, map)| map.get(&item).copied())
                .unwrap_or(false);
            out.push_str(&format!("{item}={}\n", if answer { 1 } else { 0 }));
        }
    }

    // Baseline keys the templates never mention: stale entries, or knobs like
    // `PICS_SDK_CI_ONLY` that are not PICS at all. Kept, but called out.
    if let Some((path, map)) = baseline {
        let extra: Vec<_> = map
            .iter()
            .filter(|(k, _)| !report.derived.contains_key(*k) && !report.left_items.contains(k))
            .collect();

        if !extra.is_empty() {
            out.push_str(&format!(
                "\n# ---- Present in {} but absent from the Matter 1.6 templates ----\n\
                 # Either an SDK-runner knob (e.g. PICS_SDK_CI_ONLY) or drift from an\n\
                 # older test plan. Review before trusting.\n",
                path.display()
            ));
            for (k, v) in extra {
                out.push_str(&format!("{k}={}\n", if *v { 1 } else { 0 }));
            }
        }
    }

    fs::write(path, out).with_context(|| format!("writing {}", path.display()))?;
    info!("Flat PICS written to {}", path.display());

    Ok(())
}

/// Rewrite a hand-curated `.pics` in place, correcting every key the data model
/// can decide.
///
/// Line-oriented and order-preserving: comments, blank lines, key order and
/// every entry the data model cannot answer are left exactly as they were, so
/// the resulting diff shows only the corrections.
fn fix_baseline(path: &Path, report: &Report) -> anyhow::Result<usize> {
    let text = fs::read_to_string(path).with_context(|| format!("reading {}", path.display()))?;

    let mut out = String::with_capacity(text.len());
    let mut fixed = 0;

    for line in text.split_inclusive('\n') {
        let body = line.split('#').next().unwrap_or("").trim();

        if let Some((key, value)) = body.split_once('=') {
            let key = key.trim();

            if let Some(derived) = report.derived.get(key) {
                let want = if *derived { "1" } else { "0" };

                if value.trim() != want {
                    let eol = if line.ends_with("\r\n") {
                        "\r\n"
                    } else if line.ends_with('\n') {
                        "\n"
                    } else {
                        ""
                    };

                    out.push_str(&format!("{key}={want}{eol}"));
                    fixed += 1;
                    continue;
                }
            }
        }

        out.push_str(line);
    }

    if fixed > 0 {
        fs::write(path, out).with_context(|| format!("writing {}", path.display()))?;
        info!("{}: corrected {fixed} entries", path.display());
    }

    Ok(fixed)
}

/// PICS roots that are deliberately absent from [`PICS_ROOTS`] because they do
/// not name a cluster.
///
/// Kept separate from the unmapped-cluster warning: conflating "we chose not to
/// map this" with "we forgot to map this" would train the reader to ignore the
/// warning that matters.
const NON_CLUSTER_ROOTS: &[&str] = &[
    // The general, non-cluster PICS (`Base.xml`).
    "MCORE",
    // Platform certification declarations.
    "PLAT",
    // ICD *behaviour*; the cluster itself is `ICDM`.
    "ICDB",
    // A device-type claim.
    "APPDEVICE",
    // "Casting video player" - a device type whose sub-items are manual.
    "MC",
];

/// Cluster ID to human name, for the summary printed before deriving.
///
/// Generated from the SDK's ZAP cluster definitions, the same source as
/// [`PICS_ROOTS`]; purely cosmetic, so an unknown ID simply prints as hex.
const CLUSTER_NAMES: &[(u32, &str)] = &[
    (0x0003, "Identify"),
    (0x0004, "Groups"),
    (0x0006, "On/Off"),
    (0x0008, "Level Control"),
    (0x001C, "Pulse Width Modulation"),
    (0x001D, "Descriptor"),
    (0x001E, "Binding"),
    (0x001F, "Access Control"),
    (0x0025, "Actions"),
    (0x0028, "Basic Information"),
    (0x0029, "OTA Software Update Provider"),
    (0x002A, "OTA Software Update Requestor"),
    (0x002B, "Localization Configuration"),
    (0x002C, "Time Format Localization"),
    (0x002D, "Unit Localization"),
    (0x002E, "Power Source Configuration"),
    (0x002F, "Power Source"),
    (0x0030, "General Commissioning"),
    (0x0031, "Network Commissioning"),
    (0x0032, "Diagnostic Logs"),
    (0x0033, "General Diagnostics"),
    (0x0034, "Software Diagnostics"),
    (0x0035, "Thread Network Diagnostics"),
    (0x0036, "Wi-Fi Network Diagnostics"),
    (0x0037, "Ethernet Network Diagnostics"),
    (0x0038, "Time Synchronization"),
    (0x0039, "Bridged Device Basic Information"),
    (0x003B, "Switch"),
    (0x003C, "Administrator Commissioning"),
    (0x003E, "Operational Credentials"),
    (0x003F, "Group Key Management"),
    (0x0040, "Fixed Label"),
    (0x0041, "User Label"),
    (0x0042, "Proxy Configuration"),
    (0x0043, "Proxy Discovery"),
    (0x0044, "Proxy Valid"),
    (0x0045, "Boolean State"),
    (0x0046, "ICD Management"),
    (0x0047, "Timer"),
    (0x0048, "Oven Cavity Operational State"),
    (0x0049, "Oven Mode"),
    (0x004A, "Laundry Dryer Controls"),
    (0x0050, "Mode Select"),
    (0x0051, "Laundry Washer Mode"),
    (
        0x0052,
        "Refrigerator And Temperature Controlled Cabinet Mode",
    ),
    (0x0053, "Laundry Washer Controls"),
    (0x0054, "RVC Run Mode"),
    (0x0055, "RVC Clean Mode"),
    (0x0056, "Temperature Control"),
    (0x0057, "Refrigerator Alarm"),
    (0x0059, "Dishwasher Mode"),
    (0x005B, "Air Quality"),
    (0x005C, "Smoke CO Alarm"),
    (0x005D, "Dishwasher Alarm"),
    (0x005E, "Microwave Oven Mode"),
    (0x005F, "Microwave Oven Control"),
    (0x0060, "Operational State"),
    (0x0061, "RVC Operational State"),
    (0x0062, "Scenes Management"),
    (0x0065, "Groupcast"),
    (0x0071, "HEPA Filter Monitoring"),
    (0x0072, "Activated Carbon Filter Monitoring"),
    (0x0079, "Water Tank Level Monitoring"),
    (0x0080, "Boolean State Configuration"),
    (0x0081, "Valve Configuration and Control"),
    (0x0090, "Electrical Power Measurement"),
    (0x0091, "Electrical Energy Measurement"),
    (0x0094, "Water Heater Management"),
    (0x0095, "Commodity Price"),
    (0x0097, "Messages"),
    (0x0098, "Device Energy Management"),
    (0x0099, "Energy EVSE"),
    (0x009B, "Energy Preference"),
    (0x009C, "Power Topology"),
    (0x009D, "Energy EVSE Mode"),
    (0x009E, "Water Heater Mode"),
    (0x009F, "Device Energy Management Mode"),
    (0x00A0, "Electrical Grid Conditions"),
    (0x0101, "Door Lock"),
    (0x0102, "Window Covering"),
    (0x0104, "Closure Control"),
    (0x0105, "Closure Dimension"),
    (0x0150, "Service Area"),
    (0x0200, "Pump Configuration and Control"),
    (0x0201, "Thermostat"),
    (0x0202, "Fan Control"),
    (0x0204, "Thermostat User Interface Configuration"),
    (0x0300, "Color Control"),
    (0x0301, "Ballast Configuration"),
    (0x0400, "Illuminance Measurement"),
    (0x0402, "Temperature Measurement"),
    (0x0403, "Pressure Measurement"),
    (0x0404, "Flow Measurement"),
    (0x0405, "Relative Humidity Measurement"),
    (0x0406, "Occupancy Sensing"),
    (0x040C, "Carbon Monoxide Concentration Measurement"),
    (0x040D, "Carbon Dioxide Concentration Measurement"),
    (0x0413, "Nitrogen Dioxide Concentration Measurement"),
    (0x0415, "Ozone Concentration Measurement"),
    (0x042A, "PM2.5 Concentration Measurement"),
    (0x042B, "Formaldehyde Concentration Measurement"),
    (0x042C, "PM1 Concentration Measurement"),
    (0x042D, "PM10 Concentration Measurement"),
    (
        0x042E,
        "Total Volatile Organic Compounds Concentration Measurement",
    ),
    (0x042F, "Radon Concentration Measurement"),
    (0x0430, "Soil Measurement"),
    (0x0431, "Ambient Context Sensing"),
    (0x0451, "Wi-Fi Network Management"),
    (0x0452, "Thread Border Router Management"),
    (0x0453, "Thread Network Directory"),
    (0x0503, "Wake on LAN"),
    (0x0504, "Channel"),
    (0x0505, "Target Navigator"),
    (0x0506, "Media Playback"),
    (0x0507, "Media Input"),
    (0x0508, "Low Power"),
    (0x0509, "Keypad Input"),
    (0x050A, "Content Launcher"),
    (0x050B, "Audio Output"),
    (0x050C, "Application Launcher"),
    (0x050D, "Application Basic"),
    (0x050E, "Account Login"),
    (0x050F, "Content Control"),
    (0x0510, "Content App Observer"),
    (0x0550, "Zone Management"),
    (0x0551, "Camera AV Stream Management"),
    (0x0552, "Camera AV Settings User Level Management"),
    (0x0553, "WebRTC Transport Provider"),
    (0x0554, "WebRTC Transport Requestor"),
    (0x0555, "Push AV Stream Transport"),
    (0x0556, "Chime"),
    (0x0700, "Commodity Tariff"),
    (0x0750, "Ecosystem Information"),
    (0x0751, "Commissioner Control"),
    (0x0752, "Joint Fabric Datastore"),
    (0x0753, "Joint Fabric Administrator"),
    (0x0801, "TLS Certificate Management"),
    (0x0802, "TLS Client Management"),
    (0x0B06, "Meter Identification"),
    (0x0B07, "Commodity Metering"),
    (0xFFF1FC05, "Unit Testing"),
    (0xFFF1FC06, "Fault Injection"),
    (0xFFF1FC20, "Sample MEI"),
];

/// Device type ID to name, from the SDK's `matter-devices.xml`.
const DEVICE_TYPES: &[(u16, &str)] = &[
    (0x000A, "Door Lock"),
    (0x000B, "Door Lock Controller"),
    (0x000E, "Aggregator"),
    (0x000F, "Generic Switch"),
    (0x0011, "Power Source"),
    (0x0012, "OTA Requestor"),
    (0x0013, "Bridged Node"),
    (0x0014, "OTA Provider"),
    (0x0015, "Contact Sensor"),
    (0x0016, "Root Node"),
    (0x0017, "Solar Power"),
    (0x0018, "Battery Storage"),
    (0x0019, "Secondary Network Interface"),
    (0x0022, "Speaker"),
    (0x0023, "Casting Video Player"),
    (0x0024, "Content App"),
    (0x0027, "Mode Select"),
    (0x0028, "Basic Video Player"),
    (0x0029, "Casting Video Client"),
    (0x002A, "Video Remote Control"),
    (0x002B, "Fan"),
    (0x002C, "Air Quality Sensor"),
    (0x002D, "Air Purifier"),
    (0x0041, "Water Freeze Detector"),
    (0x0042, "Water Valve"),
    (0x0043, "Water Leak Detector"),
    (0x0044, "Rain Sensor"),
    (0x0045, "Soil Sensor"),
    (0x0070, "Refrigerator"),
    (0x0071, "Temperature Controlled Cabinet"),
    (0x0072, "Room Air Conditioner"),
    (0x0073, "Laundry Washer"),
    (0x0074, "Robotic Vacuum Cleaner"),
    (0x0075, "Dishwasher"),
    (0x0076, "Smoke CO Alarm"),
    (0x0077, "Cook Surface"),
    (0x0078, "Cooktop"),
    (0x0079, "Microwave Oven"),
    (0x007A, "Extractor Hood"),
    (0x007B, "Oven"),
    (0x007C, "Laundry Dryer"),
    (0x0090, "Network Infrastructure Manager"),
    (0x0091, "Thread Border Router"),
    (0x0100, "On/Off Light"),
    (0x0101, "Dimmable Light"),
    (0x0103, "On/Off Light Switch"),
    (0x0104, "Dimmer Switch"),
    (0x0105, "Color Dimmer Switch"),
    (0x0106, "Light Sensor"),
    (0x0107, "Occupancy Sensor"),
    (0x010A, "On/Off Plug-in Unit"),
    (0x010B, "Dimmable Plug-in Unit"),
    (0x010C, "Color Temperature Light"),
    (0x010D, "Extended Color Light"),
    (0x010F, "Mounted On/Off Control"),
    (0x0110, "Mounted Dimmable Load Control"),
    (0x0130, "Joint Fabric Administrator"),
    (0x0140, "Intercom"),
    (0x0141, "Audio Doorbell"),
    (0x0142, "Camera"),
    (0x0143, "Video Doorbell"),
    (0x0144, "Floodlight Camera"),
    (0x0145, "Snapshot Camera"),
    (0x0146, "Chime"),
    (0x0147, "Camera Controller"),
    (0x0148, "Doorbell"),
    (0x0150, "Ambient Context Sensor"),
    (0x0202, "Window Covering"),
    (0x0203, "Window Covering Controller"),
    (0x0230, "Closure"),
    (0x0231, "Closure Panel"),
    (0x023E, "Closure Controller"),
    (0x0301, "Thermostat"),
    (0x0302, "Temperature Sensor"),
    (0x0303, "Pump"),
    (0x0304, "Pump Controller"),
    (0x0305, "Pressure Sensor"),
    (0x0306, "Flow Sensor"),
    (0x0307, "Humidity Sensor"),
    (0x0309, "Heat Pump"),
    (0x030A, "Thermostat Controller"),
    (0x050C, "EVSE"),
    (0x050D, "Device Energy Management"),
    (0x050F, "Water Heater"),
    (0x0510, "Electrical Sensor"),
    (0x0511, "Electrical Utility Meter"),
    (0x0512, "Meter Reference Point"),
    (0x0513, "Electrical Energy Tariff"),
    (0x0514, "Electrical Meter"),
    (0x0840, "Control Bridge"),
    (0x0850, "On/Off Sensor"),
];

/// Network Commissioning (`0x0031`) feature bits, from the SDK's own cluster
/// definition: `WI` = Wi-Fi, `TH` = Thread, `ET` = Ethernet.
const CNET_CLUSTER: u32 = 0x0031;
const CNET_FEATURE_WIFI: u32 = 1 << 0;
const CNET_FEATURE_THREAD: u32 = 1 << 1;
const CNET_FEATURE_ETHERNET: u32 = 1 << 2;

fn cluster_name(id: u32) -> Option<&'static str> {
    CLUSTER_NAMES
        .iter()
        .find_map(|(cid, name)| (*cid == id).then_some(*name))
}

/// Summarise what the tool believes the device to be, before it derives
/// anything from that belief.
///
/// Every answer downstream follows from this picture, so it is worth stating
/// plainly: a stale or wrong data-model dump is otherwise invisible until the
/// answers come out strange. (One did, during development - a dump taken
/// before a cluster was added made a correct `.pics` look like it had nine
/// over-claims.)
fn describe_node(node: &NodeInfo, endpoints: &[(u16, Vec<u16>, Vec<u32>)]) {
    info!("Device as reported by its own data model:");

    for (id, device_types, clusters) in endpoints {
        let types: Vec<&str> = device_types
            .iter()
            .map(|dt| {
                DEVICE_TYPES
                    .iter()
                    .find_map(|(code, name)| (code == dt).then_some(*name))
                    .unwrap_or("unknown device type")
            })
            .collect();

        info!(
            "  Endpoint {id}: {}",
            if types.is_empty() {
                "(no device type)".to_string()
            } else {
                types.join(", ")
            }
        );

        let named: Vec<String> = clusters
            .iter()
            .map(|c| cluster_name(*c).map_or_else(|| format!("0x{c:04X}"), |n| n.to_string()))
            .collect();

        info!("    Supported clusters: {}", named.join(", "));
    }

    if !node.clients.is_empty() {
        let named: Vec<String> = node
            .clients
            .iter()
            .map(|c| cluster_name(*c).map_or_else(|| format!("0x{c:04X}"), |n| n.to_string()))
            .collect();
        info!("  Acts as a client for: {}", named.join(", "));
    }
}

/// Answer the transport PICS from the data model rather than asking.
///
/// Which transport a node speaks is not a product question - the Network
/// Commissioning cluster states it, and exactly one of `WI`/`TH`/`ET` is set.
/// The matching diagnostics cluster (`0x0035`/`0x0036`/`0x0037`) corroborates
/// it. Asking would invite an answer that contradicts the firmware.
///
/// Radio band (2.4 vs 5GHz) and BLE support genuinely are not in the data
/// model, so those remain questions.
fn derive_transports(node: &NodeInfo, report: &mut Report) {
    let Some(cnet) = node.servers.get(&CNET_CLUSTER) else {
        return;
    };

    let wifi = cnet.feature_map & CNET_FEATURE_WIFI != 0;
    let thread = cnet.feature_map & CNET_FEATURE_THREAD != 0;
    let ethernet = cnet.feature_map & CNET_FEATURE_ETHERNET != 0;

    for (item, value) in [
        ("MCORE.COM.WIFI", wifi),
        ("MCORE.COM.THR", thread),
        ("MCORE.COM.ETH", ethernet),
        // "Wi-Fi or Thread", i.e. any non-Ethernet operational transport.
        ("MCORE.COM.WIRELESS", wifi || thread),
    ]
    .into_iter()
    .chain(
        // BLE exists to commission a device that has no IP connectivity yet.
        // An Ethernet-only node is already on the network and commissions
        // on-network, so it has no use for it.
        //
        // The spec does not forbid both - the discovery-capabilities bitmask
        // carries independent "BLE" and "on IP network" bits - so this is a
        // default rather than a certainty. A device that really does offer BLE
        // commissioning over Ethernet can say so in its baseline.
        (ethernet && !wifi && !thread).then_some(("MCORE.COM.BLE", false)),
    ) {
        report.derived.insert(item.to_string(), value);
        report.left_items.retain(|left| left != item);
    }

    // rs-matter's `DiscoveryCapabilities` (see `pairing.rs`) defines exactly
    // three bits - SOFT_AP, BLE and IP. It has neither an NFC Transport Layer
    // bit nor a Wi-Fi Public Action Frame one, so the stack cannot advertise
    // NTL or PAF commissioning whatever the product does.
    //
    // These are facts about the rs-matter version, not about the node, so they
    // do not come from the dump. Revisit if `DiscoveryCapabilities` grows the
    // corresponding bits. Note this says nothing about `MCORE.DD.NFC` - a
    // passive tag can carry the onboarding payload without the stack
    // supporting NTL, which is why that one remains a question.
    //
    // `MCORE.COM.PAF` is gated on `MCORE.DD.DISCOVERY_PAF`, so leaving it at
    // the template's `true` claims PAF commissioning against a discovery
    // capability the stack cannot offer.
    for item in ["MCORE.DD.NTL", "MCORE.DD.DISCOVERY_PAF", "MCORE.COM.PAF"] {
        report.derived.insert(item.to_string(), false);
        report.left_items.retain(|left| left != item);
    }

    // Non-concurrent commissioning describes a device that cannot hold BLE and
    // its operational network up at once. With no BLE in the picture there is
    // no concurrency to constrain, so the question does not arise.
    if ethernet && !wifi && !thread {
        report
            .derived
            .insert("MCORE.DD.NON_CONCURRENT_CONNECTION".to_string(), false);
        report
            .left_items
            .retain(|left| left != "MCORE.DD.NON_CONCURRENT_CONNECTION");
    }

    info!(
        "Transports derived from Network Commissioning features: \
         wifi={wifi} thread={thread} ethernet={ethernet}"
    );
}

/// Answer the node-wide `MCORE.*` items that no cluster's PICS root covers.
///
/// These sit in `Base.xml`, which is emitted for every device, and the CSA
/// template ships almost all of them as `true`. Anything left untouched is
/// therefore not "unanswered" but *claimed* - which is how a light with no OTA
/// cluster came to assert `MCORE.OTA.Requestor` and pull the whole TC-SU
/// suite into its test list.
///
/// Only facts the dump actually settles are derived here. Items that need a
/// human (`MCORE.ROLE.*`, the packaging questions) stay in `QUESTIONS`.
fn derive_node_wide(node: &NodeInfo, report: &mut Report) {
    const OTA_PROVIDER: u32 = 0x0029;
    const OTA_REQUESTOR: u32 = 0x002A;
    const DIAGNOSTIC_LOGS: u32 = 0x0032;
    const BRIDGED_DEVICE_BASIC_INFO: u32 = 0x0039;
    const GROUPS: u32 = 0x0004;
    const COMMISSIONER_CONTROL: u32 = 0x0751;
    const ICD_MANAGEMENT: u32 = 0x0046;

    let serves = |id: u32| node.servers.contains_key(&id);

    // Collected rather than inserted as we go: the IDM block below needs to
    // read `report.left_items` while this is still being filled.
    let mut answers: Vec<(String, bool)> = Vec::new();
    let mut set = |item: &str, value: bool| answers.push((item.to_string(), value));

    // Device types, not clusters, in the item text - but a node implementing
    // either OTA device type necessarily serves the matching cluster, and the
    // cluster is what the dump reports.
    set("MCORE.OTA.Requestor", serves(OTA_REQUESTOR));
    set("MCORE.OTA.Provider", serves(OTA_PROVIDER));

    // A commissionee that does not implement the OTA Requestor device type is
    // required to declare a vendor-specific update path instead - the template
    // makes it mandatory with `cond="MCORE.ROLE.COMMISSIONEE AND NOT
    // (MCORE.OTA.Requestor)"`, which is the CSA's way of insisting every Matter
    // device be updatable somehow. Leaving it `false` there is not a modest
    // claim but an invalid PICS, and the tool rejects the whole file.
    //
    // This is a statement about the product rather than the stack, so a device
    // that really has no update path at all should say so in its baseline.
    set("MCORE.OTA.VendorSpecific", !serves(OTA_REQUESTOR));

    // Both halves of OTA move the image over BDX: the requestor fetches with
    // `parse_bdx_url` + `Exchange::download` (which rejects an `https://` URL
    // outright), and the provider serves through `OtaBdxHandler`. No HTTPS
    // download path exists in the stack, either to offer or to consume.
    set("MCORE.OTA.HTTPS", false);

    // A bridge exposes its bridged devices through Bridged Device Basic
    // Information. Without that cluster there is nothing bridged to describe,
    // so neither the bridge itself nor any of its per-device claims hold.
    let bridge = serves(BRIDGED_DEVICE_BASIC_INFO);
    set("MCORE.BRIDGE", bridge);
    if !bridge {
        for item in [
            "MCORE.BRIDGE.BatInfo",
            "MCORE.BRIDGE.OtherControl",
            "MCORE.BRIDGE.AllowDeviceRename",
        ] {
            set(item, false);
        }
    }

    // Fabric Synchronization is driven through Commissioner Control.
    set("MCORE.FS", serves(COMMISSIONER_CONTROL));

    // Both items name fields of `RetrieveLogsResponse`, which only exists if
    // the cluster does.
    if !serves(DIAGNOSTIC_LOGS) {
        set("MCORE.DLOG.S.UTCTIMESTAMP", false);
        set("MCORE.DLOG.S.TIMESINCEBOOT", false);
    }

    // Literally "multiple endpoints with a Groups cluster" - countable.
    let group_endpoints = node
        .endpoints
        .iter()
        .filter(|(_, _, clusters)| clusters.contains(&GROUPS))
        .count();
    set("MCORE.G.MULTIENDPOINT", group_endpoints > 1);

    // The IDM client items all begin "Is the device a Client and ...". A node
    // that binds no client clusters is not an IDM client, so every one of them
    // is false. The converse is not derivable - which data types a client
    // reads or writes is not in the dump - so a node that does have client
    // clusters leaves them alone.
    set("MCORE.IDM.S", !node.servers.is_empty());
    let client = !node.clients.is_empty();
    set("MCORE.IDM.C", client);
    if !client {
        for item in report
            .left_items
            .iter()
            .filter(|i| i.starts_with("MCORE.IDM.C"))
        {
            set(item, false);
        }
    }

    // BDX roles.
    //
    // BDX is a protocol rather than a cluster, so it never appears in the dump
    // directly. Within rs-matter it has exactly two users, though, and each
    // pins down which roles the node can play:
    //
    //   Diagnostic Logs (0x0032) server  uploads logs   -> Sender,   Initiator
    //   Diagnostic Logs client           receives them  -> Receiver, Responder
    //   OTA Provider    (0x0029)         serves images  -> Sender,   Responder
    //   OTA Requestor   (0x002A)         fetches images -> Receiver, Initiator
    //
    // A node serving none of them has no BDX user at all, and that direction is
    // conclusive: the template's blanket `true` becomes `false`. The positive
    // direction is a strong default rather than a certainty - the application
    // must also wire the handler up (`Bdx::new(OtaBdxHandler::new(..))`) - so a
    // device that does not can say so in its baseline.
    let dlog_client = node.clients.contains(&DIAGNOSTIC_LOGS);
    let sender = serves(DIAGNOSTIC_LOGS) || serves(OTA_PROVIDER);
    let receiver = serves(OTA_REQUESTOR) || dlog_client;
    let initiator = serves(DIAGNOSTIC_LOGS) || serves(OTA_REQUESTOR);
    let responder = serves(OTA_PROVIDER) || dlog_client;

    for (item, value) in [
        ("MCORE.BDX.Sender", sender),
        ("MCORE.BDX.Receiver", receiver),
        ("MCORE.BDX.Initiator", initiator),
        ("MCORE.BDX.Responder", responder),
        // Synchronous is the only mode rs-matter ever negotiates, so these
        // simply mirror the roles above.
        ("MCORE.BDX.SynchronousSender", sender),
        ("MCORE.BDX.SynchronousReceiver", receiver),
        // `TransferControl::async_mode` is documented "Provisional - never
        // selected by a Responder", and negotiation proposes it as `false`.
        ("MCORE.BDX.AsynchronousSender", false),
        ("MCORE.BDX.AsynchronousReceiver", false),
        // Both drive modes are proposed and both are implemented (the receiver
        // paces with `BlockQuery` in `bdx::read`, the sender in `bdx::write`),
        // so a node doing BDX at all can drive the transfer.
        ("MCORE.BDX.Driver", sender || receiver),
        // The message type is defined and parsed, but `BlockQueryWithSkip` is
        // only ever *constructed* in `bdx.rs`'s own unit tests. Nothing in the
        // stack sends one, which is what this item asks.
        ("MCORE.BDX.BlockQueryWithSkip", false),
    ] {
        set(item, value);
    }

    // The DNS-SD items ask which optional TXT keys and subtypes the node
    // advertises. That is exactly what the mDNS half of the dump records, so
    // it is read off rather than asked.
    let comm = &node.mdns.commissionable_txt;
    let oper = &node.mdns.operational_txt;
    let subtype = |prefix: &str| {
        node.mdns
            .commissionable_subtypes
            .iter()
            .any(|s| s.starts_with(prefix))
    };

    for (item, present) in [
        ("MCORE.SC.VP_KEY", comm.contains("VP")),
        ("MCORE.SC.DT_KEY", comm.contains("DT")),
        ("MCORE.SC.DN_KEY", comm.contains("DN")),
        ("MCORE.SC.RI_KEY", comm.contains("RI")),
        ("MCORE.SC.PH_KEY", comm.contains("PH")),
        ("MCORE.SC.PI_KEY", comm.contains("PI")),
        ("MCORE.SC.SII_COMM_DISCOVERY_KEY", comm.contains("SII")),
        ("MCORE.SC.SAI_COMM_DISCOVERY_KEY", comm.contains("SAI")),
        ("MCORE.SC.SII_OP_DISCOVERY_KEY", oper.contains("SII")),
        ("MCORE.SC.SAI_OP_DISCOVERY_KEY", oper.contains("SAI")),
        ("MCORE.SC.SAT_OP_DISCOVERY_KEY", oper.contains("SAT")),
        ("MCORE.SC.T_KEY", oper.contains("T")),
        ("MCORE.SC.VENDOR_SUBTYPE", subtype("_V")),
        ("MCORE.SC.DEVTYPE_SUBTYPE", subtype("_T")),
        // The same facts, asked again under the Device Discovery root.
        ("MCORE.DD.TXT_KEY_VP", comm.contains("VP")),
        ("MCORE.DD.TXT_KEY_DT", comm.contains("DT")),
        ("MCORE.DD.TXT_KEY_DN", comm.contains("DN")),
        ("MCORE.DD.TXT_KEY_RI", comm.contains("RI")),
        ("MCORE.DD.TXT_KEY_PH", comm.contains("PH")),
        ("MCORE.DD.TXT_KEY_PI", comm.contains("PI")),
        ("MCORE.DD.COMMISSIONING_SUBTYPE_V", subtype("_V")),
        ("MCORE.DD.COMMISSIONING_SUBTYPE_T", subtype("_T")),
        // The operational `T` key is the TCP support bitmap, and the stack
        // emits it only when `dev_det.tcp_supported` is set (empty values are
        // filtered out of the TXT record). Its presence is therefore exactly
        // the question this item asks - and it gates the whole TC-SC-8 suite.
        ("MCORE.SC.TCP", oper.contains("T")),
        // Large-payload interactions ride on TCP, so they cannot be supported
        // by a node that does not advertise it.
        ("MCORE.IDM.S.LargeData", oper.contains("T")),
        // A Short Idle Time ICD is an ICD, and an ICD serves ICD Management.
        ("MCORE.SC.SIT_ICD", serves(ICD_MANAGEMENT)),
    ] {
        set(item, present);
    }

    report.derived.extend(answers);
    report
        .left_items
        .retain(|left| !report.derived.contains_key(left));

    info!(
        "Node-wide PICS derived: OTA requestor={} provider={}, bridge={bridge}, \
         IDM client={client}, mDNS commissionable TXT {:?}",
        serves(OTA_REQUESTOR),
        serves(OTA_PROVIDER),
        node.mdns.commissionable_txt
    );
}

/// A high-level question standing in for a group of PICS items that the data
/// model cannot answer.
///
/// The point is leverage: the master set has ~2800 items, of which the data
/// model decides ~90%. Of the remainder, a handful of facts about the
/// *product* - what it is plugged into, whether it has buttons - settle most
/// of the rest. Answering eight questions beats ticking forty boxes in the
/// PICS Tool, and is far harder to get quietly wrong.
struct Question {
    /// Asked verbatim; phrased so that "yes" always means "supported".
    prompt: &'static str,
    /// Items this answer settles. A trailing `*` matches by prefix.
    items: &'static [&'static str],
    /// PICS items that must already have been *derived as supported* for the
    /// question to apply.
    ///
    /// The master templates express this themselves - `PS.S.M.ManualBatFault`
    /// carries `cond="PS.S AND PS.S.F01"` - and the conditions are usually
    /// feature bits, which the data model decides. Asking a mains-only device
    /// whether it can induce a *battery* fault invites a wrong answer to a
    /// question that never applied.
    requires: &'static [&'static str],
}

/// Only asked when the templates in play actually contain the items, so a
/// simple light is never asked about ovens or power-source faults.
const QUESTIONS: &[Question] = &[
    // ---- Transports -------------------------------------------------------
    // Wi-Fi / Thread / Ethernet are derived in `derive_transports`; only the
    // radio band and BLE are genuinely outside the data model.
    Question {
        prompt: "Does the device support communication over 2.4GHz Wi-Fi?",
        items: &["MCORE.COM.WIFI_2P4GHZ"],
        requires: &["MCORE.COM.WIFI"],
    },
    Question {
        prompt: "Does the device support communication over 5GHz Wi-Fi?",
        items: &["MCORE.COM.WIFI_5GHZ"],
        requires: &["MCORE.COM.WIFI"],
    },
    Question {
        // Only meaningful for a device that must be commissioned onto a network
        // it cannot already reach; `derive_transports` settles it directly for
        // Ethernet-only nodes.
        prompt: "Does the device support communication over Bluetooth Low Energy (BLE)?",
        items: &["MCORE.COM.BLE"],
        requires: &["MCORE.COM.WIRELESS"],
    },
    // ---- Roles ------------------------------------------------------------
    // Not in the data model: a node's commissioner/controller role is a
    // property of the application, not of its published clusters.
    Question {
        prompt: "Does the device implement a Commissioner?",
        items: &["MCORE.ROLE.COMMISSIONER"],
        requires: &[],
    },
    Question {
        prompt: "Does the device implement a Controller?",
        items: &["MCORE.ROLE.CONTROLLER"],
        requires: &[],
    },
    // Commissioner-side capabilities. The templates gate these on the role
    // (`cond="MCORE.ROLE.COMMISSIONER AND MCORE.COM.BLE"` for the first), so a
    // plain commissionee is never asked.
    // ---- Controller-side claims -------------------------------------------
    // These describe a node that *manages other devices*, not one that is
    // managed. The templates leave them ungated and default them to `true`, so
    // a plain device would otherwise claim it maintains a device list and holds
    // Administer privilege on other nodes. Gating them on the Controller answer
    // settles all six as `false` without asking a device anything.
    Question {
        prompt: "Does the controller maintain a list of connected devices?",
        items: &["MCORE.DEVLIST.UseDevices"],
        requires: &["MCORE.ROLE.CONTROLLER"],
    },
    Question {
        prompt: "Does that device list track names, state and battery level?",
        items: &[
            "MCORE.DEVLIST.UseDeviceName",
            "MCORE.DEVLIST.UseDeviceState",
            "MCORE.DEVLIST.UseBatInfo",
        ],
        requires: &["MCORE.ROLE.CONTROLLER", "MCORE.DEVLIST.UseDevices"],
    },
    Question {
        prompt: "Can the controller talk to bridged devices behind a Bridge?",
        items: &["MCORE.BRIDGECLIENT"],
        requires: &["MCORE.ROLE.CONTROLLER"],
    },
    Question {
        prompt: "Does the device hold Administer privilege over another node's Access Control?",
        items: &["MCORE.ACL.Administrator"],
        requires: &["MCORE.ROLE.CONTROLLER"],
    },
    Question {
        prompt: "Does the commissioner support Discovery Capability over BLE?",
        items: &["MCORE.DD.DISCOVERY_BLE"],
        requires: &["MCORE.ROLE.COMMISSIONER", "MCORE.COM.BLE"],
    },
    Question {
        prompt: "Does the commissioner support scanning NFC tags containing the onboarding payload?",
        items: &["MCORE.DD.SCAN_NFC"],
        requires: &["MCORE.ROLE.COMMISSIONER"],
    },
    // ---- Onboarding payload, as physically supplied ------------------------
    // Whether a code is actually printed on the device or its box is a
    // packaging decision, invisible to the firmware.
    //
    // Deliberately *not* gated on this item's own `cond`, which reads
    // `MCORE.DD.CONCATENATED_QR_CODE`: taken literally that would only ask
    // about a QR code on multi-device packages, and suppress the question for
    // every ordinary single-device product.
    Question {
        prompt: "Does the device or its packaging carry a QR-code onboarding payload?",
        items: &["MCORE.DD.QR"],
        requires: &[],
    },
    Question {
        prompt: "Does the device or its packaging carry a manual pairing code?",
        items: &["MCORE.DD.MANUAL_PC"],
        requires: &[],
    },
    Question {
        prompt: "Does the device have an NFC tag containing the onboarding payload?",
        items: &["MCORE.DD.NFC"],
        requires: &[],
    },
    // ---- Physical / product properties ------------------------------------
    Question {
        prompt: "Does the device support a user interface?",
        items: &["MCORE.DD.UI"],
        requires: &[],
    },
    Question {
        // `cond="CADMIN.C"` - only meaningful where the node is an
        // Administrator Commissioning *client*, which the data model knows.
        prompt: "Does the device support a User Interface Display?",
        items: &["CADMIN.C.M.UserInterfaceDisplay"],
        requires: &["CADMIN.C"],
    },
    Question {
        prompt: "Does the device support an Audio Interface?",
        items: &["CADMIN.C.M.AudioInterface"],
        requires: &["CADMIN.C"],
    },
    Question {
        prompt: "Is the device subject to physical tampering (doorbell, camera, door lock, outdoor use)?",
        items: &["MCORE.DD.PHYSICAL_TAMPERING"],
        requires: &[],
    },
    Question {
        prompt: "Does the device require the non-concurrent connection commissioning flow \
                 (BLE and the operational network cannot be up at the same time)?",
        items: &["MCORE.DD.NON_CONCURRENT_CONNECTION"],
        requires: &["MCORE.COM.BLE"],
    },
    Question {
        prompt: "Is the device a software component rather than a finished product?",
        items: &["MCORE.DT_SW_COMP"],
        requires: &[],
    },
    Question {
        // Template wording: "Can the OnOff attribute changed by physical
        // control at the device?". Gates the operator prompts in `TC_OO_2_2`
        // steps 6a-6d, where a human toggles the device by hand and the
        // harness reads `OnOff` back.
        prompt: "Can OnOff be changed by a physical control on the device (a switch or button on the unit itself)?",
        items: &["OO.M.ManuallyControlled"],
        requires: &["OO.S"],
    },
    Question {
        // Template wording is "Can the configuration of the DUT be changed at
        // run-time?", which reads far broader than it is - it is not about
        // writable attributes. `TC_BINFO_3_2` step 2 is explicit: a change
        // "which results in functionality to be added or removed (e.g. rewire
        // thermostat to support a new mode)", after which `ConfigurationVersion`
        // must read strictly higher.
        //
        // Core spec 9.2.11 permits two causes: a change in "installation or
        // configuration of the device", and a firmware update that adds or
        // removes functionality. It is not firmware-only - the spec's own
        // example of a bridge gaining or losing a bridged node is a
        // configuration change requiring no OTA.
        //
        // For a typical rs-matter device the answer is nonetheless `no`, but
        // for an implementation reason rather than a spec one: `Node` is a
        // compile-time const, so composition cannot change without new
        // firmware and a restart. A future bridge that gains bridged endpoints
        // at run time would legitimately answer `yes`.
        prompt: "Can the device's functional composition change while it is running (clusters or endpoints \
                 added/removed without an OTA and restart), such that ConfigurationVersion must increment?",
        items: &["BINFO.S.M.DeviceConfigurationChange"],
        requires: &["BINFO.S"],
    },
    // ---- Power source faults ----------------------------------------------
    // Three separate questions, each gated on the feature bit the template's
    // own `cond` names. Lumping them into one would let a mains-only device
    // claim it can induce a battery fault. Each gates the corresponding
    // operator steps in `TC_PS_2_2` ("Bring the DUT into a ... fault state").
    Question {
        prompt: "Can the device be brought into a Wired Fault state on demand?",
        items: &["PS.S.M.ManualWiredFault"],
        requires: &["PS.S.F00"],
    },
    Question {
        prompt: "Can the device be brought into a Battery Fault state on demand?",
        items: &["PS.S.M.ManualBatFault"],
        requires: &["PS.S.F01"],
    },
    Question {
        prompt: "Can the device be brought into a Battery Charge Fault state on demand?",
        items: &["PS.S.M.ManualBatChargeFault"],
        requires: &["PS.S.F02"],
    },
    // ---- Localization ------------------------------------------------------
    // Which units/formats are actually offered is not modelled; both are gated
    // on their cluster being served, per the templates' `cond`.
    Question {
        prompt: "Does the device support the Celsius temperature unit?",
        items: &["LUNIT.S.M.Celsius"],
        requires: &["LUNIT.S"],
    },
    Question {
        prompt: "Does the device support the Fahrenheit temperature unit?",
        items: &["LUNIT.S.M.Fahrenheit"],
        requires: &["LUNIT.S"],
    },
    Question {
        prompt: "Does the device support the Kelvin temperature unit?",
        items: &["LUNIT.S.M.Kelvin"],
        requires: &["LUNIT.S"],
    },
    Question {
        prompt: "Does the device support the 12-hour time format?",
        items: &["LTIME.S.M.12Hr"],
        requires: &["LTIME.S"],
    },
    Question {
        prompt: "Does the device support the 24-hour time format?",
        items: &["LTIME.S.M.24Hr"],
        requires: &["LTIME.S"],
    },
    // ---- OTA behaviours ----------------------------------------------------
    // `MCORE.OTA.Requestor` / `Provider` are derived from cluster presence;
    // these are behaviours of the implementation that the data model cannot
    // see, and only matter for a Requestor.
    Question {
        prompt: "Does the device obtain user consent before applying an OTA update?",
        items: &["MCORE.OTA.RequestorConsent"],
        requires: &["MCORE.OTA.Requestor"],
    },
    Question {
        prompt: "Can the device resume an OTA transfer that was previously aborted?",
        items: &["MCORE.OTA.Resume"],
        requires: &["MCORE.OTA.Requestor"],
    },
    Question {
        prompt: "Can the device query a different Provider from its OTA Provider List on error?",
        items: &["MCORE.OTA.Retry"],
        requires: &["MCORE.OTA.Requestor"],
    },
];

impl Question {
    /// Which of this question's items are still unanswered.
    fn pending<'a>(&self, unanswered: &'a BTreeSet<String>) -> Vec<&'a String> {
        unanswered
            .iter()
            .filter(|item| {
                self.items.iter().any(|pat| {
                    pat.strip_suffix('*')
                        .map_or(*pat == item.as_str(), |prefix| item.starts_with(prefix))
                })
            })
            .collect()
    }
}

/// Ask the operator the handful of product questions the data model cannot
/// answer, and fold the results into the derived set.
///
/// Skipped entirely when stdin is not a terminal: a CI run must not block on a
/// prompt, and silently inventing answers would be worse than leaving them.
fn ask_questions(report: &mut Report, baseline: Option<&BTreeMap<String, bool>>) {
    // Candidates: items the templates carry, the data model could not decide,
    // and no baseline already answers.
    let unanswered: BTreeSet<String> = report
        .left_items
        .iter()
        .filter(|item| baseline.is_none_or(|map| !map.contains_key(*item)))
        .cloned()
        .collect();

    if unanswered.is_empty() {
        return;
    }

    // A question's `requires` mirrors the `cond` the template puts on the same
    // items. When it does not hold, the item is not merely unasked - it is
    // inapplicable, and the only truthful support value is `false`.
    //
    // Gating the *question* is therefore only half the job: leaving the
    // *answer* at the template's `true` is what let `MCORE.DD.DISCOVERY_BLE`
    // claim BLE discovery on a device deriving no BLE, which the CSA PICS tool
    // reports as a dependency violation.
    //
    // Answering `false` is also the safe direction: an unsupported claim
    // merely skips test cases, whereas an unbacked `true` schedules tests the
    // device cannot pass.
    //
    // Whether a question applies can depend on the answer to an *earlier* one:
    // the device-list claims only arise for a Controller, which is itself a
    // question. So the list is walked in declaration order and `requires` is
    // evaluated against the answers so far, rather than once up front.
    let interactive = std::io::stdin().is_terminal();
    let mut unasked: Vec<(&Question, usize)> = Vec::new();
    let mut announced = false;
    let mut asked = 0;

    for question in QUESTIONS {
        // `unanswered` also holds manual `.M.` behaviours and stale keys that
        // no question covers; those are nobody's to answer and are skipped.
        let pending = question.pending(&unanswered);
        if pending.is_empty() {
            continue;
        }

        let applies = question
            .requires
            .iter()
            .all(|item| report.derived.get(*item).copied().unwrap_or(false));

        if !applies {
            for item in pending {
                report.derived.insert(item.clone(), false);
            }
            continue;
        }

        if !interactive {
            unasked.push((question, pending.len()));
            continue;
        }

        if !announced {
            info!("");
            info!(
                "Questions about the product, settling PICS items the data model cannot \
                 answer. Enter y or n; anything else keeps the template's value."
            );
            announced = true;
        }

        print!("  {} [y/n] ", question.prompt);
        let _ = std::io::Write::flush(&mut std::io::stdout());

        let mut line = String::new();
        if std::io::stdin().read_line(&mut line).is_err() {
            break;
        }

        let answer = match line.trim().to_ascii_lowercase().as_str() {
            "y" | "yes" => true,
            "n" | "no" => false,
            _ => continue,
        };

        for item in pending {
            report.derived.insert(item.clone(), answer);
        }
        asked += 1;
    }

    // Answered items are no longer open, so they must not keep counting
    // towards "still need manual input".
    report
        .left_items
        .retain(|left| !report.derived.contains_key(left));

    if !unasked.is_empty() {
        let items: usize = unasked.iter().map(|(_, n)| n).sum();
        warn!(
            "{} question(s) covering {items} item(s) need a product-level answer, but stdin \
             is not a terminal - leaving them as the template had them. Re-run interactively, \
             or supply a `--baseline` that already answers them:",
            unasked.len()
        );
        for (question, n) in &unasked {
            warn!("    {} [{}]", question.prompt, n);
        }
    }

    if asked > 0 {
        info!("Answered {asked} question(s).");
    }

    info!("");
}

/// Report how much of a baseline the tool was actually able to check.
///
/// Without this, a `.pics` full of clusters absent from [`PICS_ROOTS`] lints
/// "clean" simply because nothing was looked at - which is a far more
/// dangerous answer than a list of conflicts. Every entry is accounted for.
fn report_coverage(path: &Path, baseline: &BTreeMap<String, bool>, report: &Report) {
    let mut checked = 0usize;
    let mut not_cluster = 0usize;
    let mut unmapped: BTreeMap<&str, usize> = BTreeMap::new();
    let mut undecidable: BTreeMap<&str, usize> = BTreeMap::new();

    for item in baseline.keys() {
        if report.derived.contains_key(item) {
            checked += 1;
            continue;
        }

        let root = item.split('.').next().unwrap_or(item);

        // `MCORE.*`, `PIXIT.*` and the SDK runner knobs are not cluster PICS
        // and are out of scope by construction, not by omission.
        if root == "PIXIT" || root.starts_with("PICS_") || NON_CLUSTER_ROOTS.contains(&root) {
            not_cluster += 1;
        } else if PICS_ROOTS.iter().any(|(name, _)| *name == root) {
            // Cluster is known, but this particular item is one the data model
            // cannot decide - a manual `.M.` behaviour, or a key that no longer
            // appears in the templates.
            *undecidable.entry(root).or_default() += 1;
        } else {
            *unmapped.entry(root).or_default() += 1;
        }
    }

    let total = baseline.len();
    info!(
        "{}: {checked}/{total} entries checked, {not_cluster} out of scope \
         (MCORE/PIXIT/knobs/device types)",
        path.display()
    );

    if !undecidable.is_empty() {
        let n: usize = undecidable.values().sum();
        info!("    {n} not decidable from the data model (manual items / stale keys):");
        for (root, count) in &undecidable {
            info!("        {root:<14} {count:>4}");
        }
    }

    if !unmapped.is_empty() {
        let n: usize = unmapped.values().sum();
        warn!(
            "    {n} entries NOT CHECKED - cluster missing from PICS_ROOTS, so these were \
             silently skipped rather than validated:"
        );
        for (root, count) in &unmapped {
            warn!("        {root:<14} {count:>4}");
        }
        warn!("    Add these clusters to `PICS_ROOTS` to close the gap.");
    }
}

/// Report where a hand-curated `.pics` disagrees with the data model.
fn lint_baseline(path: &Path, baseline: &BTreeMap<String, bool>, report: &Report) {
    let mut conflicts: Vec<(&String, bool, bool)> = baseline
        .iter()
        .filter_map(|(item, claimed)| {
            let derived = *report.derived.get(item)?;
            (derived != *claimed).then_some((item, *claimed, derived))
        })
        .collect();
    conflicts.sort();

    if conflicts.is_empty() {
        info!(
            "{} agrees with the data model on every entry it declares",
            path.display()
        );
    } else {
        warn!(
            "{} disagrees with the data model on {} item(s):",
            path.display(),
            conflicts.len()
        );
        for (item, claimed, derived) in conflicts {
            warn!(
                "    {item:<28} claims {} but the device serves {}",
                u8::from(claimed),
                u8::from(derived)
            );
        }
    }

    // Agreeing on what the file says is only half an audit - see below.
    report_omissions(baseline, report);
}

/// Report items the data model derives as *supported* that the baseline never
/// mentions.
///
/// The conflict check compares only entries the file already has, which leaves
/// it blind in the direction that actually costs coverage: in the flat format a
/// missing key reads as unsupported, so an omitted item silently gates its own
/// tests off. A file can therefore be "in full agreement" while declaring a
/// fraction of the device.
///
/// This is the check `TC_pics_checker` performs against the live device ("An
/// element found on the device, but the corresponding PICS ... was not found in
/// pics list"); running it found 151 such items in `light_tests.pics` that no
/// amount of linting here would have surfaced.
///
/// Informational rather than a warning, because an omission is not wrong by
/// itself: the `tests/src/bin/*.pics` files are deliberately scoped to the
/// suite that consumes them, and carrying the whole data model would be noise.
/// In a PICS submitted for certification the same omission is an under-claim.
fn report_omissions(baseline: &BTreeMap<String, bool>, report: &Report) {
    let mut missing: BTreeMap<&str, usize> = BTreeMap::new();

    for (item, derived) in &report.derived {
        // Only a *supported* item can be under-claimed by omission. One derived
        // `false` says the same thing whether it is written out or left out.
        if !derived || baseline.contains_key(item) {
            continue;
        }

        let root = item.split('.').next().unwrap_or(item);
        *missing.entry(root).or_default() += 1;
    }

    if missing.is_empty() {
        return;
    }

    let n: usize = missing.values().sum();
    info!(
        "    {n} supported item(s) are not declared at all - a missing key reads as \
         unsupported, so any test gated on one skips:"
    );
    for (root, count) in &missing {
        info!("        {root:<14} {count:>4}");
    }
    info!(
        "    Expected where the file is scoped to a single suite; an under-claim in a \
         PICS submitted for certification."
    );
}

/// Whether a path names a ZIP archive rather than a directory.
fn is_zip(path: &Path) -> bool {
    path.extension()
        .is_some_and(|e| e.eq_ignore_ascii_case("zip"))
}

/// Load the master templates from either a directory or the CSA ZIP exactly as
/// downloaded, so it need not be unpacked first.
///
/// Entries are keyed by base name: the archive nests everything under a
/// top-level directory, which is not worth carrying into the output.
fn load_templates(path: &Path) -> anyhow::Result<Vec<(String, String)>> {
    let mut templates = Vec::new();

    if is_zip(path) {
        let file = fs::File::open(path).with_context(|| format!("opening {}", path.display()))?;
        let mut archive =
            zip::ZipArchive::new(file).with_context(|| format!("reading {}", path.display()))?;

        for i in 0..archive.len() {
            let mut entry = archive.by_index(i)?;
            if !entry.is_file() || !entry.name().to_ascii_lowercase().ends_with(".xml") {
                continue;
            }

            let name = Path::new(entry.name())
                .file_name()
                .map(|n| n.to_string_lossy().into_owned())
                .unwrap_or_else(|| entry.name().to_string());

            let mut xml = String::new();
            entry
                .read_to_string(&mut xml)
                .with_context(|| format!("reading {name} from {}", path.display()))?;

            templates.push((name, xml));
        }
    } else {
        for entry in fs::read_dir(path)
            .with_context(|| format!("reading template directory {}", path.display()))?
        {
            let p = entry?.path();
            if !p.extension().is_some_and(|e| e.eq_ignore_ascii_case("xml")) {
                continue;
            }

            let name = p.file_name().unwrap().to_string_lossy().into_owned();
            let xml = fs::read_to_string(&p).with_context(|| format!("reading {}", p.display()))?;

            templates.push((name, xml));
        }
    }

    templates.sort_by(|a, b| a.0.cmp(&b.0));

    Ok(templates)
}

/// Write the filled templates to either a directory or a ZIP, chosen by the
/// extension of `path`.
fn write_templates(path: &Path, files: &[(String, String)]) -> anyhow::Result<()> {
    if is_zip(path) {
        if let Some(parent) = path.parent().filter(|p| !p.as_os_str().is_empty()) {
            fs::create_dir_all(parent)?;
        }

        let file =
            fs::File::create(path).with_context(|| format!("creating {}", path.display()))?;
        let mut zip = zip::ZipWriter::new(file);
        let options = zip::write::SimpleFileOptions::default()
            .compression_method(zip::CompressionMethod::Deflated);

        for (name, xml) in files {
            zip.start_file(name.as_str(), options)?;
            zip.write_all(xml.as_bytes())?;
        }

        zip.finish()?;
    } else {
        fs::create_dir_all(path).with_context(|| format!("creating {}", path.display()))?;

        for (name, xml) in files {
            let dest = path.join(name);
            fs::write(&dest, xml).with_context(|| format!("writing {}", dest.display()))?;
        }
    }

    Ok(())
}

/// Fill every template in `templates` from `node`, writing the results to `out`.
pub fn run(
    templates: &Path,
    node: &Path,
    out: Option<&Path>,
    pics: Option<&Path>,
    baseline: Option<&Path>,
    fix: bool,
) -> anyhow::Result<()> {
    let node_path = node;
    let node_json =
        fs::read_to_string(node).with_context(|| format!("reading {}", node.display()))?;
    let node = NodeInfo::parse(&node_json)?;

    describe_node(&node, &node.endpoints.clone());

    let files = load_templates(templates)?;

    if files.is_empty() {
        return Err(anyhow!(
            "no .xml templates found in {} - point `--templates` at the CSA master \
             PICS set, either as the downloaded .zip or unpacked into a directory",
            templates.display()
        ));
    }

    let mut total = Report::default();
    // Retained templates are kept as their *source*, not as a rendering. The
    // answers that `derive_transports` and `ask_questions` settle do not exist
    // yet at this point, so anything rendered here would carry the template's
    // own defaults for them. Rendering happens once, below, after every answer
    // is in.
    let mut retained: Vec<(&str, &str)> = Vec::new();

    for (name, xml) in &files {
        let mut report = Report::default();
        // No settled answers yet - this pass exists to work out which
        // templates are about this device, and what the data model alone can
        // decide.
        let _ = fill_template(xml, &node, &BTreeMap::new(), &mut report);

        // Only emit templates that are about *this* device.
        //
        // Every template yields derivable answers now - a cluster the node does
        // not serve makes all of its items `false` - so "did we answer
        // anything?" no longer discriminates and would emit 123 of 126 files.
        // What a reader wants is the handful describing clusters the device
        // actually has, plus the general (non-cluster) PICS, which always
        // apply.
        // `MCORE` is the general, node-wide PICS (`Base.xml`) and always
        // applies. The other non-cluster roots do not get this treatment: they
        // are *about* something - `ICDB` about ICD Management, `MC` about the
        // casting video player - and would otherwise drag in a whole template
        // for a cluster the device does not have.
        let relevant = report.roots.iter().any(|root| {
            root == "MCORE"
                || PICS_ROOTS.iter().any(|(name, id)| {
                    name == root && (node.servers.contains_key(id) || node.clients.contains(id))
                })
        });

        if !relevant {
            continue;
        }

        retained.push((name.as_str(), xml.as_str()));

        info!(
            "{:<48} {:>4} rewritten, {:>4} already correct",
            name, report.changed, report.confirmed
        );

        total.changed += report.changed;
        total.confirmed += report.confirmed;
        total.derived.extend(report.derived);
        total.left_items.extend(report.left_items);
        for (root, n) in report.left {
            *total.left.entry(root).or_default() += n;
        }
    }

    // Settle everything the templates alone could not, before any consumer
    // looks at the answers - the linter, the flat `.pics` and the XML must all
    // see the same set.
    derive_transports(&node, &mut total);
    derive_node_wide(&node, &mut total);

    let baseline_map = baseline
        .map(|p| {
            fs::read_to_string(p)
                .with_context(|| format!("reading baseline {}", p.display()))
                .map(|t| parse_flat(&t))
        })
        .transpose()?;

    if let (Some(p), Some(map)) = (baseline, baseline_map.as_ref()) {
        report_coverage(p, map, &total);
        lint_baseline(p, map, &total);
    }

    if out.is_some() || pics.is_some() || fix {
        ask_questions(&mut total, baseline_map.as_ref());
    }

    // `left` was counted while filling the templates, before the two steps
    // above answered some of what it counted. Recount from the items that are
    // still open, or the summary reports as unanswered what was just answered.
    total.left.clear();
    for item in &total.left_items {
        let root = item.split('.').next().unwrap_or(item);
        *total.left.entry(root.to_string()).or_default() += 1;
    }

    info!("");
    info!(
        "Derived {} answers ({} rewritten, {} already matching the template)",
        total.changed + total.confirmed,
        total.changed,
        total.confirmed
    );

    let left: usize = total.left.values().sum();
    if left > 0 {
        // Informational, not a warning: these are the items the data model was
        // never going to answer. `warn!` overstates it, and since the xtask
        // logger indents by severity it also drops the block out of line with
        // everything around it. Genuine problems - unmapped clusters, baseline
        // disagreements - keep their `warn!`.
        info!("{left} items left untouched - these still need manual input:");
        for (root, n) in &total.left {
            info!("    {root:<12} {n:>4}");
        }
    }

    if let (Some(p), true) = (baseline, fix) {
        fix_baseline(p, &total)?;
    }

    if let Some(pics) = pics {
        write_flat(pics, node_path, &total, baseline.zip(baseline_map.as_ref()))?;
    }

    if let Some(out) = out {
        // Render now, with every answer in hand. Doing it during the first
        // pass would emit the template's own default for anything settled
        // afterwards: that is how `MCORE.COM.WIFI` stayed `true` on an
        // Ethernet-only device, contradicting the `CNET.S.F00` it gates and
        // failing the PICS tool's dependency check in all three Network
        // Commissioning files.
        let filled: Vec<(String, String)> = retained
            .iter()
            .map(|(name, xml)| {
                let mut rendered = Report::default();
                (
                    (*name).to_string(),
                    fill_template(xml, &node, &total.derived, &mut rendered),
                )
            })
            .collect();

        write_templates(out, &filled)?;
        info!(
            "{} filled templates written to {}",
            filled.len(),
            out.display()
        );
    }

    // Deriving without asking for any output is a legitimate dry run, but it
    // should say so - otherwise an invocation that simply forgot `--out` looks
    // indistinguishable from one that worked.
    if out.is_none() && pics.is_none() && !fix {
        info!("Nothing written (no --out, --pics or --fix given); this was a dry run.");
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;

    use super::{NON_CLUSTER_ROOTS, PICS_ROOTS};

    /// The table maps PICS roots onto cluster IDs, and `resolve` looks a root up
    /// by name. A duplicate ID therefore answers one cluster's items against
    /// another cluster's data model - silently, and with full confidence.
    ///
    /// This is not hypothetical: `CONCON` (Content Control) was once mapped to
    /// `0x0506`, which is Media Playback, so every `CONCON.*` item was answered
    /// from the wrong cluster. It survived because the duplicate check was run
    /// while the table had 41 entries and not again after it grew to 132.
    #[test]
    fn pics_roots_have_no_duplicate_ids() {
        let mut by_id: BTreeMap<u32, Vec<&str>> = BTreeMap::new();
        for (root, id) in PICS_ROOTS {
            by_id.entry(*id).or_default().push(root);
        }

        let dups: Vec<_> = by_id.iter().filter(|(_, roots)| roots.len() > 1).collect();

        assert!(
            dups.is_empty(),
            "cluster ID(s) claimed by more than one PICS root: {dups:?}"
        );
    }

    /// A repeated root would make the lookup order-dependent, so the second
    /// entry would be dead code that looks authoritative.
    #[test]
    fn pics_roots_have_no_duplicate_names() {
        let mut names: Vec<&str> = PICS_ROOTS.iter().map(|(root, _)| *root).collect();
        names.sort_unstable();

        let before = names.len();
        names.dedup();

        assert_eq!(before, names.len(), "PICS_ROOTS contains a repeated root");
    }

    /// Kept sorted by cluster ID purely so that additions land next to their
    /// neighbours and a wrong ID looks wrong in review.
    #[test]
    fn pics_roots_are_sorted_by_id() {
        let ids: Vec<u32> = PICS_ROOTS.iter().map(|(_, id)| *id).collect();

        let mut sorted = ids.clone();
        sorted.sort_unstable();

        assert_eq!(ids, sorted, "PICS_ROOTS is no longer sorted by cluster ID");
    }

    /// The two lists express opposite intents: "this root is a cluster, here is
    /// its ID" and "this root is deliberately not a cluster". A root in both
    /// would mean the exclusion never takes effect.
    #[test]
    fn non_cluster_roots_are_not_also_mapped() {
        for root in NON_CLUSTER_ROOTS {
            assert!(
                !PICS_ROOTS.iter().any(|(name, _)| name == root),
                "{root} is in NON_CLUSTER_ROOTS but also mapped in PICS_ROOTS"
            );
        }
    }
}
