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

//! Per-module summary of a `cargo llvm-cov` LCOV trace.
//!
//! `cargo llvm-cov --lcov` reports per file. This groups those files by module
//! path under `rs-matter/src`, so a coverage report can be read at the level
//! the crate is organised: depth 1 gives one row per top-level module (`dm`,
//! `transport`, ...), depth 2 splits those (`dm/clusters`, `transport/network`,
//! ...), depth 0 is a single crate total. A file sitting at the requested depth
//! (`acl.rs` at depth 1) forms a row of its own, and a module's own file
//! (`dm.rs` next to `dm/`) is folded into the module's row.
//!
//! `--split-above N` keeps `--depth` for small modules but breaks a module with
//! more than N instrumented lines down one level further, so a report stays
//! short while the big modules are not reduced to a single average.
//!
//! Only line coverage is aggregated: it is the figure compared across tools,
//! and region/branch data does not survive LCOV in a comparable form.

use std::collections::BTreeMap;
use std::fs;
use std::path::{Path, PathBuf};

use anyhow::{bail, Context};

use clap::Args as ClapArgs;

/// The path prefix that identifies the crate's sources in an LCOV record.
const SRC_MARKER: &str = "rs-matter/src/";

/// Arguments of the `coverage` sub-command.
#[derive(ClapArgs, Clone, Debug)]
pub struct Args {
    /// LCOV trace file, as written by `cargo llvm-cov --lcov --output-path <file>`
    lcov: PathBuf,
    /// Module depth to group by: 0 is a crate total, 1 one row per top-level
    /// module, 2 splits those into `dm/clusters`, `transport/network`, ...
    #[arg(long, default_value_t = 2)]
    depth: usize,
    /// Break modules with more than this many instrumented lines down one
    /// level further than `--depth`
    #[arg(long, value_name = "LINES")]
    split_above: Option<usize>,
    /// Also list the N lowest-covered files
    #[arg(long, value_name = "N", default_value_t = 0)]
    lowest: usize,
    /// Ignore files with fewer instrumented lines than this in `--lowest`
    #[arg(long, default_value_t = 50)]
    min_lines: usize,
    /// Emit a Markdown table (for a CI job summary)
    #[arg(long)]
    markdown: bool,
}

/// Line coverage of one source file.
struct FileCov {
    source: String,
    found: usize,
    hit: usize,
}

/// Line coverage of one report row (a module or a file).
#[derive(Default)]
struct Row {
    found: usize,
    hit: usize,
    files: usize,
}

impl Row {
    fn pct(&self) -> f64 {
        if self.found > 0 {
            100.0 * self.hit as f64 / self.found as f64
        } else {
            0.0
        }
    }
}

/// Summarize `args.lcov` and print the report.
pub fn run(args: &Args) -> anyhow::Result<()> {
    let files = parse_lcov(&args.lcov)?;
    if files.is_empty() {
        bail!("{}: no file records found", args.lcov.display());
    }

    let rows = aggregate(&files, args.depth, args.split_above);

    let lowest = (args.lowest > 0).then(|| {
        let mut per_file: Vec<_> = aggregate(&files, usize::MAX, None)
            .into_iter()
            .filter(|(_, row)| row.found >= args.min_lines)
            .collect();
        sort_by_coverage(&mut per_file);
        per_file.truncate(args.lowest);
        per_file
    });

    print!("{}", render(rows, lowest, args.min_lines, args.markdown));

    Ok(())
}

/// Read the `SF`/`LF`/`LH` fields of every record in an LCOV trace.
fn parse_lcov(path: &Path) -> anyhow::Result<Vec<FileCov>> {
    let text = fs::read_to_string(path).with_context(|| format!("reading {}", path.display()))?;

    let mut files = Vec::new();
    let mut current: Option<FileCov> = None;

    for line in text.lines() {
        if let Some(source) = line.strip_prefix("SF:") {
            current = Some(FileCov {
                source: source.to_string(),
                found: 0,
                hit: 0,
            });
        } else if let Some(found) = line.strip_prefix("LF:") {
            if let Some(cov) = current.as_mut() {
                cov.found = found
                    .parse()
                    .with_context(|| format!("bad LF line: {line}"))?;
            }
        } else if let Some(hit) = line.strip_prefix("LH:") {
            if let Some(cov) = current.as_mut() {
                cov.hit = hit
                    .parse()
                    .with_context(|| format!("bad LH line: {line}"))?;
            }
        } else if line == "end_of_record" {
            files.extend(current.take());
        }
    }

    Ok(files)
}

/// The row a source file belongs to at `depth`.
///
/// `rs-matter/src/dm/clusters/on_off.rs` is `dm/clusters/on_off` at depth 3
/// or more, `dm/clusters` at depth 2 and `dm` at depth 1.
fn module_key(source: &str, depth: usize) -> String {
    if depth == 0 {
        return "(crate)".to_string();
    }

    let rel = source
        .find(SRC_MARKER)
        .map(|idx| &source[idx + SRC_MARKER.len()..])
        .unwrap_or(source);

    let mut parts: Vec<&str> = rel.split('/').collect();

    if parts.len() > depth {
        parts.truncate(depth);
    } else if let Some(last) = parts.last_mut() {
        // A file at or above the requested depth: `dm.rs` -> `dm`
        let name: &str = last;
        *last = name.strip_suffix(".rs").unwrap_or(name);
    }

    parts.join("/")
}

/// Group the files into rows at `depth`, breaking rows larger than
/// `split_above` lines down one more level.
fn aggregate(files: &[FileCov], depth: usize, split_above: Option<usize>) -> BTreeMap<String, Row> {
    let mut rows = BTreeMap::<String, Row>::new();

    for file in files {
        let row = rows.entry(module_key(&file.source, depth)).or_default();
        row.found += file.found;
        row.hit += file.hit;
        row.files += 1;
    }

    let Some(split_above) = split_above else {
        return rows;
    };

    let big: Vec<String> = rows
        .iter()
        .filter(|(_, row)| row.found > split_above)
        .map(|(name, _)| name.clone())
        .collect();

    if big.is_empty() {
        return rows;
    }

    let mut split = BTreeMap::<String, Row>::new();

    for file in files {
        let mut name = module_key(&file.source, depth);
        if big.contains(&name) {
            name = module_key(&file.source, depth + 1);
        }

        let row = split.entry(name).or_default();
        row.found += file.found;
        row.hit += file.hit;
        row.files += 1;
    }

    split
}

/// Lowest coverage first; equal coverage in name order.
fn sort_by_coverage(rows: &mut [(String, Row)]) {
    rows.sort_by(|(a_name, a), (b_name, b)| {
        a.pct()
            .partial_cmp(&b.pct())
            .unwrap_or(std::cmp::Ordering::Equal)
            .then_with(|| a_name.cmp(b_name))
    });
}

fn render(
    rows: BTreeMap<String, Row>,
    lowest: Option<Vec<(String, Row)>>,
    min_lines: usize,
    markdown: bool,
) -> String {
    let total = rows.values().fold(Row::default(), |acc, row| Row {
        found: acc.found + row.found,
        hit: acc.hit + row.hit,
        files: acc.files + row.files,
    });

    let mut ordered: Vec<_> = rows.into_iter().collect();
    sort_by_coverage(&mut ordered);

    let mut out = String::new();

    if markdown {
        out.push_str("| Module | Lines | Covered | Files |\n|---|---:|---:|---:|\n");
        for (name, row) in &ordered {
            out.push_str(&format!(
                "| `{name}` | {} | {:.1}% | {} |\n",
                row.found,
                row.pct(),
                row.files
            ));
        }
        out.push_str(&format!(
            "| **total** | {} | **{:.1}%** | {} |\n",
            total.found,
            total.pct(),
            total.files
        ));
    } else {
        let width = ordered
            .iter()
            .map(|(name, _)| name.len())
            .max()
            .unwrap_or(10);

        out.push_str(&format!(
            "{:<width$}  {:>7}  {:>8}  files\n",
            "module", "lines", "covered"
        ));
        for (name, row) in &ordered {
            out.push_str(&format!(
                "{name:<width$}  {:>7}  {:>7.1}%  {}\n",
                row.found,
                row.pct(),
                row.files
            ));
        }
        out.push_str(&format!(
            "{:<width$}  {:>7}  {:>7.1}%\n",
            "total",
            total.found,
            total.pct()
        ));
    }

    if let Some(lowest) = lowest {
        out.push_str(&format!("\nLowest-covered files (>= {min_lines} lines):\n"));
        for (name, row) in lowest {
            out.push_str(&format!(
                "  {:>5.1}%  {:>6} lines  {name}\n",
                row.pct(),
                row.found
            ));
        }
    }

    out
}

#[cfg(test)]
mod tests {
    use super::*;

    const TRACE: &str = "\
SF:/w/rs-matter/src/dm.rs
LF:10
LH:5
end_of_record
SF:/w/rs-matter/src/dm/clusters/on_off.rs
LF:100
LH:20
end_of_record
SF:/w/rs-matter/src/dm/types/cluster.rs
LF:40
LH:40
end_of_record
SF:/w/rs-matter/src/acl.rs
LF:50
LH:45
end_of_record
";

    fn files() -> Vec<FileCov> {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("lcov.info");
        fs::write(&path, TRACE).unwrap();
        parse_lcov(&path).unwrap()
    }

    #[test]
    fn keys_follow_the_module_tree() {
        let src = "/w/rs-matter/src/dm/clusters/on_off.rs";
        assert_eq!(module_key(src, 0), "(crate)");
        assert_eq!(module_key(src, 1), "dm");
        assert_eq!(module_key(src, 2), "dm/clusters");
        assert_eq!(module_key(src, 3), "dm/clusters/on_off");
        assert_eq!(module_key(src, 9), "dm/clusters/on_off");
        assert_eq!(module_key("/w/rs-matter/src/dm.rs", 1), "dm");
        assert_eq!(module_key("/w/rs-matter/src/dm.rs", 2), "dm");
    }

    #[test]
    fn rows_fold_a_module_file_into_its_module() {
        let rows = aggregate(&files(), 1, None);
        let dm = &rows["dm"];
        assert_eq!((dm.found, dm.hit, dm.files), (150, 65, 3));
        assert_eq!(rows["acl"].files, 1);
        assert_eq!(rows.len(), 2);
    }

    #[test]
    fn large_modules_are_split_one_level_further() {
        let rows = aggregate(&files(), 1, Some(100));
        assert_eq!(rows["dm"].found, 10);
        assert_eq!(rows["dm/clusters"].found, 100);
        assert_eq!(rows["dm/types"].found, 40);
        assert_eq!(rows["acl"].found, 50);

        // Nothing is large enough: the plain depth-1 rows come back
        assert_eq!(aggregate(&files(), 1, Some(1000)).len(), 2);
    }

    #[test]
    fn report_is_ordered_lowest_first_with_a_total() {
        let text = render(aggregate(&files(), 1, None), None, 50, false);
        let lines: Vec<_> = text.lines().collect();
        assert!(lines[1].starts_with("dm "), "{text}");
        assert!(lines[2].starts_with("acl "), "{text}");
        assert!(lines[3].starts_with("total "), "{text}");
        assert!(lines[3].contains("200"), "{text}");
        assert!(lines[3].contains("55.0%"), "{text}");
    }
}
