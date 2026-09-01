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
use std::path::{Path, PathBuf};

use anyhow::{anyhow, Context};
use log::{info, warn};

/// PICS root (as used in item numbers) to Matter cluster ID.
///
/// The master templates leave `<clusterId>` empty in every file, so the cluster
/// a template describes can only be recovered from the prefix of its item
/// numbers. Each entry below was checked against the corresponding
/// `* Cluster Test Plan.xml` in the Matter 1.6 master set.
const PICS_ROOTS: &[(&str, u32)] = &[
    ("I", 0x0003),
    ("G", 0x0004),
    ("OO", 0x0006),
    ("LVL", 0x0008),
    ("DESC", 0x001D),
    ("BIND", 0x001E),
    ("ACL", 0x001F),
    ("BINFO", 0x0028),
    ("CGEN", 0x0030),
    ("CNET", 0x0031),
    ("DGGEN", 0x0033),
    ("DGSW", 0x0034),
    ("DGETH", 0x0037),
    ("TIMESYNC", 0x0038),
    ("SWTCH", 0x003B),
    ("CADMIN", 0x003C),
    ("OPCREDS", 0x003E),
    ("GRPKEY", 0x003F),
    ("CC", 0x0300),
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

        let info = server?;

        // Attributes: `A` + 4 hex digits.
        if let Some(hex) = sub.strip_prefix('A') {
            let id = u32::from_str_radix(hex, 16).ok()?;
            return Some(info.attributes.contains(&id));
        }

        // Feature bits: `F` + 2 hex digits.
        if let Some(hex) = sub.strip_prefix('F') {
            let bit = u32::from_str_radix(hex, 16).ok()?;
            return Some(info.feature_map & (1 << bit) != 0);
        }

        // Events: `E` + 2 hex digits.
        if let Some(hex) = sub.strip_prefix('E') {
            let id = u32::from_str_radix(hex, 16).ok()?;
            return Some(info.events.contains(&id));
        }

        // Commands: `C` + 2 hex digits, then `.Rsp` (received) or `.Tx` (generated).
        if let Some(rest) = sub.strip_prefix('C') {
            let (hex, dir) = rest.split_once('.')?;
            let id = u32::from_str_radix(hex, 16).ok()?;

            return match dir {
                "Rsp" => Some(info.commands_received.contains(&id)),
                "Tx" => Some(info.commands_generated.contains(&id)),
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

                        out.push_str(&replacement);
                        continue;
                    }

                    let root = name.split('.').next().unwrap_or(name);
                    *report.left.entry(root.to_string()).or_default() += 1;
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

/// Fill every template in `templates` from `node`, writing the results to `out`.
pub fn run(templates: &Path, node: &Path, out: &Path) -> anyhow::Result<()> {
    let node_json =
        fs::read_to_string(node).with_context(|| format!("reading {}", node.display()))?;
    let node = NodeInfo::parse(&node_json)?;

    info!(
        "Device serves {} clusters ({} as client)",
        node.servers.len(),
        node.clients.len()
    );

    let mut files: Vec<PathBuf> = fs::read_dir(templates)
        .with_context(|| format!("reading template directory {}", templates.display()))?
        .filter_map(Result::ok)
        .map(|e| e.path())
        .filter(|p| p.extension().is_some_and(|e| e.eq_ignore_ascii_case("xml")))
        .collect();
    files.sort();

    if files.is_empty() {
        return Err(anyhow!(
            "no .xml templates found in {} - point `--templates` at the unpacked \
             CSA master PICS set",
            templates.display()
        ));
    }

    fs::create_dir_all(out).with_context(|| format!("creating {}", out.display()))?;

    let mut total = Report::default();

    for path in &files {
        let xml =
            fs::read_to_string(path).with_context(|| format!("reading {}", path.display()))?;

        let mut report = Report::default();
        let filled = fill_template(&xml, &node, &mut report);

        // Only emit templates this device has something to say about; copying
        // the other ~100 unchanged would bury the meaningful output.
        if report.changed + report.confirmed == 0 {
            continue;
        }

        let dest = out.join(path.file_name().unwrap());
        fs::write(&dest, filled).with_context(|| format!("writing {}", dest.display()))?;

        info!(
            "{:<48} {:>4} rewritten, {:>4} already correct",
            path.file_name().unwrap().to_string_lossy(),
            report.changed,
            report.confirmed
        );

        total.changed += report.changed;
        total.confirmed += report.confirmed;
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

    info!("Filled templates written to {}", out.display());

    Ok(())
}
