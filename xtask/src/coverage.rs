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

//! Per-module summary of one or more `cargo llvm-cov` LCOV traces.
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
//! Several traces (say the host test suites and the CHIP certification suites)
//! are shown side by side, one column each, plus a column for their union: a
//! line counts as covered in the union if any trace covers it. `--merge-out`
//! writes that union as an LCOV trace of its own, for tools that take one.
//!
//! Only line coverage is aggregated: it is the figure compared across tools,
//! and region/branch data does not survive LCOV in a comparable form.

use std::collections::BTreeMap;
use std::fmt::Write as _;
use std::fs;
use std::path::{Path, PathBuf};

use anyhow::{bail, Context};

use clap::Args as ClapArgs;

/// The path prefix that identifies the crate's sources in an LCOV record.
const SRC_MARKER: &str = "rs-matter/src/";

/// The name of the union column when several traces are given.
const UNION: &str = "all";

/// Arguments of the `coverage` sub-command.
#[derive(ClapArgs, Clone, Debug)]
pub struct Args {
    /// LCOV trace file(s), as written by `cargo llvm-cov --lcov --output-path <file>`.
    /// With several, each gets a column and their union a further one
    #[arg(required = true)]
    lcov: Vec<PathBuf>,
    /// Column names for the traces, in order (default: the file stems)
    #[arg(long, value_delimiter = ',')]
    names: Vec<String>,
    /// Module depth to group by: 0 is a crate total, 1 one row per top-level
    /// module, 2 splits those into `dm/clusters`, `transport/network`, ...
    #[arg(long, default_value_t = 2)]
    depth: usize,
    /// Break modules with more than this many instrumented lines down one
    /// level further than `--depth`
    #[arg(long, value_name = "LINES")]
    split_above: Option<usize>,
    /// Also list the N lowest-covered files (by the union, with several traces)
    #[arg(long, value_name = "N", default_value_t = 0)]
    lowest: usize,
    /// Ignore files with fewer instrumented lines than this in `--lowest`
    #[arg(long, default_value_t = 50)]
    min_lines: usize,
    /// Write the union of the traces as an LCOV trace to this file
    #[arg(long, value_name = "FILE")]
    merge_out: Option<PathBuf>,
    /// Emit a Markdown table (for a CI job summary)
    #[arg(long)]
    markdown: bool,
}

/// Line coverage of one source file: execution count per instrumented line.
#[derive(Clone, Default)]
struct FileCov {
    lines: BTreeMap<u32, u64>,
}

impl FileCov {
    fn found(&self) -> usize {
        self.lines.len()
    }

    fn hit(&self) -> usize {
        self.lines.values().filter(|&&hits| hits > 0).count()
    }
}

/// A trace: coverage per source file.
type Trace = BTreeMap<String, FileCov>;

/// Line coverage of one report row (a module or a file).
#[derive(Clone, Copy, Default)]
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

    fn add(&mut self, cov: &FileCov) {
        self.found += cov.found();
        self.hit += cov.hit();
        self.files += 1;
    }
}

/// The rows of one column, keyed by module (or file) name.
type Rows = BTreeMap<String, Row>;

/// Summarize the traces and print the report.
pub fn run(args: &Args) -> anyhow::Result<()> {
    let traces = args
        .lcov
        .iter()
        .map(|path| parse_lcov(path))
        .collect::<anyhow::Result<Vec<_>>>()?;

    if traces.iter().all(Trace::is_empty) {
        bail!("no file records found in the given trace(s)");
    }

    let names: Vec<String> = args
        .lcov
        .iter()
        .enumerate()
        .map(|(i, path)| {
            args.names.get(i).cloned().unwrap_or_else(|| {
                path.file_stem()
                    .map(|stem| stem.to_string_lossy().into_owned())
                    .unwrap_or_else(|| format!("trace{}", i + 1))
            })
        })
        .collect();

    let union = merge(&traces);

    if let Some(out) = &args.merge_out {
        fs::write(out, write_lcov(&union)).with_context(|| format!("writing {}", out.display()))?;
    }

    // The union defines the row set; with a single trace it is that trace
    let mut columns: Vec<(String, Rows)> = Vec::new();
    if traces.len() > 1 {
        for (name, trace) in names.iter().zip(&traces) {
            columns.push((name.clone(), aggregate(trace, args.depth, args.split_above)));
        }
    }
    columns.push((
        if traces.len() > 1 {
            UNION.to_string()
        } else {
            names[0].clone()
        },
        aggregate(&union, args.depth, args.split_above),
    ));

    let lowest = (args.lowest > 0).then(|| {
        let mut per_file: Vec<_> = aggregate(&union, usize::MAX, None)
            .into_iter()
            .filter(|(_, row)| row.found >= args.min_lines)
            .collect();
        sort_by_coverage(&mut per_file);
        per_file.truncate(args.lowest);
        per_file
    });

    print!(
        "{}",
        render(&columns, lowest, args.min_lines, args.markdown)
    );

    Ok(())
}

/// Read the `SF`/`DA` records of an LCOV trace.
fn parse_lcov(path: &Path) -> anyhow::Result<Trace> {
    let text = fs::read_to_string(path).with_context(|| format!("reading {}", path.display()))?;

    let mut trace = Trace::new();
    let mut current: Option<(String, FileCov)> = None;

    for line in text.lines() {
        if let Some(source) = line.strip_prefix("SF:") {
            current = Some((source.to_string(), FileCov::default()));
        } else if let Some(da) = line.strip_prefix("DA:") {
            if let Some((_, cov)) = current.as_mut() {
                // `DA:<line>,<hits>[,<checksum>]`
                let mut fields = da.split(',');
                let lineno: u32 = fields
                    .next()
                    .and_then(|s| s.parse().ok())
                    .with_context(|| format!("bad DA line: {line}"))?;
                let hits: u64 = fields
                    .next()
                    .and_then(|s| s.parse().ok())
                    .with_context(|| format!("bad DA line: {line}"))?;
                *cov.lines.entry(lineno).or_default() += hits;
            }
        } else if line == "end_of_record" {
            if let Some((source, cov)) = current.take() {
                merge_file(trace.entry(source).or_default(), &cov);
            }
        }
    }

    Ok(trace)
}

/// Add `other`'s execution counts to `into`, line by line.
fn merge_file(into: &mut FileCov, other: &FileCov) {
    for (&lineno, &hits) in &other.lines {
        *into.lines.entry(lineno).or_default() += hits;
    }
}

/// The union of several traces.
fn merge(traces: &[Trace]) -> Trace {
    let mut union = Trace::new();

    for trace in traces {
        for (source, cov) in trace {
            merge_file(union.entry(source.clone()).or_default(), cov);
        }
    }

    union
}

/// Serialize a trace in LCOV format (line records only).
fn write_lcov(trace: &Trace) -> String {
    let mut out = String::new();

    for (source, cov) in trace {
        let _ = writeln!(out, "SF:{source}");
        for (lineno, hits) in &cov.lines {
            let _ = writeln!(out, "DA:{lineno},{hits}");
        }
        let _ = writeln!(out, "LF:{}", cov.found());
        let _ = writeln!(out, "LH:{}", cov.hit());
        out.push_str("end_of_record\n");
    }

    out
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
fn aggregate(trace: &Trace, depth: usize, split_above: Option<usize>) -> Rows {
    let mut rows = Rows::new();

    for (source, cov) in trace {
        rows.entry(module_key(source, depth)).or_default().add(cov);
    }

    let Some(split_above) = split_above else {
        return rows;
    };

    let big: Vec<&String> = rows
        .iter()
        .filter(|(_, row)| row.found > split_above)
        .map(|(name, _)| name)
        .collect();

    if big.is_empty() {
        return rows;
    }

    let mut split = Rows::new();

    for (source, cov) in trace {
        let mut name = module_key(source, depth);
        if big.contains(&&name) {
            name = module_key(source, depth + 1);
        }

        split.entry(name).or_default().add(cov);
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

/// Render the columns as a table ordered by the last (union) column, plus
/// the lowest-covered files.
fn render(
    columns: &[(String, Rows)],
    lowest: Option<Vec<(String, Row)>>,
    min_lines: usize,
    markdown: bool,
) -> String {
    let (_, union) = columns.last().expect("at least one column");

    let mut ordered: Vec<(String, Row)> = union
        .iter()
        .map(|(name, row)| (name.clone(), *row))
        .collect();
    sort_by_coverage(&mut ordered);

    // Per column: the percentage of every row, and the total
    let cells: Vec<(Vec<String>, Row)> = columns
        .iter()
        .map(|(_, rows)| {
            let total = rows.values().fold(Row::default(), |acc, row| Row {
                found: acc.found + row.found,
                hit: acc.hit + row.hit,
                files: acc.files + row.files,
            });
            let pcts = ordered
                .iter()
                .map(|(name, _)| match rows.get(name) {
                    Some(row) if row.found > 0 => format!("{:.1}%", row.pct()),
                    _ => "-".to_string(),
                })
                .collect();
            (pcts, total)
        })
        .collect();

    let mut out = String::new();

    if markdown {
        out.push_str("| Module | Lines |");
        for (name, _) in columns {
            let _ = write!(out, " {name} |");
        }
        out.push_str(" Files |\n|---|---:|");
        for _ in columns {
            out.push_str("---:|");
        }
        out.push_str("---:|\n");

        for (i, (name, row)) in ordered.iter().enumerate() {
            let _ = write!(out, "| `{name}` | {} |", row.found);
            for (pcts, _) in &cells {
                let _ = write!(out, " {} |", pcts[i]);
            }
            let _ = writeln!(out, " {} |", row.files);
        }

        let (_, union_total) = cells.last().expect("at least one column");
        let _ = write!(out, "| **total** | {} |", union_total.found);
        for (_, total) in &cells {
            let _ = write!(out, " **{:.1}%** |", total.pct());
        }
        let _ = writeln!(out, " {} |", union_total.files);
    } else {
        let width = ordered
            .iter()
            .map(|(name, _)| name.len())
            .max()
            .unwrap_or(10)
            .max("module".len());
        let col = columns
            .iter()
            .map(|(name, _)| name.len())
            .max()
            .unwrap_or(0)
            .max("100.0%".len());

        let _ = write!(out, "{:<width$}  {:>7}", "module", "lines");
        for (name, _) in columns {
            let _ = write!(out, "  {name:>col$}");
        }
        out.push_str("  files\n");

        for (i, (name, row)) in ordered.iter().enumerate() {
            let _ = write!(out, "{name:<width$}  {:>7}", row.found);
            for (pcts, _) in &cells {
                let _ = write!(out, "  {:>col$}", pcts[i]);
            }
            let _ = writeln!(out, "  {}", row.files);
        }

        let (_, union_total) = cells.last().expect("at least one column");
        let _ = write!(out, "{:<width$}  {:>7}", "total", union_total.found);
        for (_, total) in &cells {
            let _ = write!(out, "  {:>col$}", format!("{:.1}%", total.pct()));
        }
        out.push('\n');
    }

    if let Some(lowest) = lowest {
        let _ = writeln!(out, "\nLowest-covered files (>= {min_lines} lines):");
        for (name, row) in lowest {
            let _ = writeln!(out, "  {:>5.1}%  {:>6} lines  {name}", row.pct(), row.found);
        }
    }

    out
}

#[cfg(test)]
mod tests {
    use super::*;

    const TRACE_A: &str = "\
SF:/w/rs-matter/src/dm.rs
DA:1,1
DA:2,0
end_of_record
SF:/w/rs-matter/src/dm/clusters/on_off.rs
DA:10,3
DA:11,0
DA:12,0
DA:13,0
end_of_record
SF:/w/rs-matter/src/acl.rs
DA:5,1
DA:6,1
end_of_record
";

    const TRACE_B: &str = "\
SF:/w/rs-matter/src/dm/clusters/on_off.rs
DA:10,1
DA:11,2
DA:12,0
DA:13,0
end_of_record
SF:/w/rs-matter/src/dm/types/cluster.rs
DA:7,4
end_of_record
";

    fn trace(text: &str) -> Trace {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("lcov.info");
        fs::write(&path, text).unwrap();
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
    fn line_records_are_counted_per_file() {
        let a = trace(TRACE_A);
        let on_off = &a["/w/rs-matter/src/dm/clusters/on_off.rs"];
        assert_eq!((on_off.found(), on_off.hit()), (4, 1));
    }

    #[test]
    fn rows_fold_a_module_file_into_its_module() {
        let rows = aggregate(&trace(TRACE_A), 1, None);
        let dm = &rows["dm"];
        assert_eq!((dm.found, dm.hit, dm.files), (6, 2, 2));
        assert_eq!(rows["acl"].files, 1);
        assert_eq!(rows.len(), 2);
    }

    #[test]
    fn large_modules_are_split_one_level_further() {
        let rows = aggregate(&trace(TRACE_A), 1, Some(3));
        assert_eq!(rows["dm"].found, 2);
        assert_eq!(rows["dm/clusters"].found, 4);
        assert_eq!(rows["acl"].found, 2);

        // Nothing is large enough: the plain depth-1 rows come back
        assert_eq!(aggregate(&trace(TRACE_A), 1, Some(1000)).len(), 2);
    }

    #[test]
    fn union_covers_a_line_when_any_trace_does() {
        let union = merge(&[trace(TRACE_A), trace(TRACE_B)]);

        let on_off = &union["/w/rs-matter/src/dm/clusters/on_off.rs"];
        assert_eq!(on_off.lines[&10], 4);
        assert_eq!(on_off.lines[&11], 2);
        assert_eq!((on_off.found(), on_off.hit()), (4, 2));

        // Files present in only one trace are carried over unchanged
        assert_eq!(union["/w/rs-matter/src/acl.rs"].hit(), 2);
        assert_eq!(union["/w/rs-matter/src/dm/types/cluster.rs"].hit(), 1);
        assert_eq!(union.len(), 4);
    }

    #[test]
    fn written_union_reads_back_identically() {
        let union = merge(&[trace(TRACE_A), trace(TRACE_B)]);
        let again = trace(&write_lcov(&union));

        assert_eq!(again.len(), union.len());
        for (source, cov) in &union {
            assert_eq!(again[source].lines, cov.lines, "{source}");
        }
    }

    #[test]
    fn report_shows_a_column_per_trace_plus_the_union() {
        let a = trace(TRACE_A);
        let b = trace(TRACE_B);
        let union = merge(&[a.clone(), b.clone()]);
        let columns = vec![
            ("own".to_string(), aggregate(&a, 1, None)),
            ("chip".to_string(), aggregate(&b, 1, None)),
            (UNION.to_string(), aggregate(&union, 1, None)),
        ];

        let text = render(&columns, None, 50, false);
        let lines: Vec<_> = text.lines().collect();
        assert!(lines[0].contains("own") && lines[0].contains("chip") && lines[0].contains("all"));
        // `dm`: own 2/6, chip 3/5, union 4/7 - the lowest union row comes first
        assert!(lines[1].starts_with("dm "), "{text}");
        assert!(
            lines[1].contains("33.3%") && lines[1].contains("60.0%") && lines[1].contains("57.1%"),
            "{text}"
        );
        // `acl` is absent from the chip trace
        assert!(
            lines[2].starts_with("acl ") && lines[2].contains(" - "),
            "{text}"
        );
        assert!(lines[3].starts_with("total "), "{text}");
    }
}
