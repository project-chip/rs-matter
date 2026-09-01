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
use std::io::{Read, Write};
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
    ("CONCON", 0x0506),
    ("MEDIAPLAYBACK", 0x0506),
    ("MEDIAINPUT", 0x0507),
    ("LOWPOWER", 0x0508),
    ("KEYPADINPUT", 0x0509),
    ("CONTENTLAUNCHER", 0x050A),
    ("AUDIOOUTPUT", 0x050B),
    ("APPLAUNCHER", 0x050C),
    ("APBSC", 0x050D),
    ("ALOGIN", 0x050E),
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

        let endpoints = v["endpoints"]
            .as_array()
            .ok_or_else(|| anyhow!("no `endpoints`"))?;

        for ep in endpoints {
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

        Ok(Self { servers, clients })
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
}

/// Rewrite every `<support>` this tool can answer, preserving the file
/// byte-for-byte otherwise.
///
/// Deliberately line-oriented rather than a real XML round-trip: the output
/// must stay diffable against the CSA original, so that what changed is
/// reviewable.
fn fill_template(xml: &str, node: &NodeInfo, report: &mut Report) -> String {
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
                    if let Some(answer) = node.resolve(name) {
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
        info!("{} agrees with the data model", path.display());
        return;
    }

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

    info!(
        "Device serves {} clusters ({} as client)",
        node.servers.len(),
        node.clients.len()
    );

    let files = load_templates(templates)?;

    if files.is_empty() {
        return Err(anyhow!(
            "no .xml templates found in {} - point `--templates` at the CSA master \
             PICS set, either as the downloaded .zip or unpacked into a directory",
            templates.display()
        ));
    }

    let mut total = Report::default();
    let mut filled_files: Vec<(String, String)> = Vec::new();

    for (name, xml) in &files {
        let mut report = Report::default();
        let filled = fill_template(xml, &node, &mut report);

        // Only emit templates this device has something to say about; copying
        // the other ~100 unchanged would bury the meaningful output.
        if report.changed + report.confirmed == 0 {
            continue;
        }

        filled_files.push((name.clone(), filled));

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

    info!("");
    info!(
        "Derived {} answers ({} rewritten, {} already matching the template)",
        total.changed + total.confirmed,
        total.changed,
        total.confirmed
    );

    let left: usize = total.left.values().sum();
    if left > 0 {
        warn!("{left} items left untouched - these still need a human:");
        for (root, n) in &total.left {
            warn!("    {root:<12} {n:>4}");
        }
    }

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

        if fix {
            fix_baseline(p, &total)?;
        }
    }

    if let Some(pics) = pics {
        write_flat(pics, node_path, &total, baseline.zip(baseline_map.as_ref()))?;
    }

    if let Some(out) = out {
        write_templates(out, &filled_files)?;
        info!(
            "{} filled templates written to {}",
            filled_files.len(),
            out.display()
        );
    }

    Ok(())
}
