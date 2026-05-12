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

//! Copyright header maintenance for `.rs` source files.
//!
//! Walks every `.rs` file tracked by GIT that lives under a crate's `src/`,
//! `tests/`, or top-level `build.rs`. For each file the first- and last-commit
//! years are derived from `git log --follow` and the canonical
//! `Copyright (c) ... Project CHIP Authors` line is rewritten accordingly.
//!
//! Files with no header at all get the full Apache-2.0 block prepended.

use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;

use anyhow::{anyhow, bail, Context};

use clap::Subcommand;

use log::{debug, error, info};

/// Canonical Apache-2.0 header used in the project. The literal string `{YEARS}`
/// is the placeholder for the computed year span. Sourced from
/// `rs-matter/src/lib.rs`.
const HEADER_TEMPLATE: &str = "/*
 *
 *    Copyright (c) {YEARS} Project CHIP Authors
 *
 *    Licensed under the Apache License, Version 2.0 (the \"License\");
 *    you may not use this file except in compliance with the License.
 *    You may obtain a copy of the License at
 *
 *        http://www.apache.org/licenses/LICENSE-2.0
 *
 *    Unless required by applicable law or agreed to in writing, software
 *    distributed under the License is distributed on an \"AS IS\" BASIS,
 *    WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *    See the License for the specific language governing permissions and
 *    limitations under the License.
 */
";

/// Marker substring used to detect an existing header.
const HEADER_MARKER: &str = "Project CHIP Authors";

/// Number of leading lines that we scan when looking for an existing header.
/// Headers always live at the top of the file.
const HEADER_SCAN_LINES: usize = 25;

/// Commits whose touches to a file should be ignored for the purpose of
/// computing its copyright year span. Each entry is the full 40-character
/// SHA-1.
///
/// The motivating case is the bulk rewrite that fixed *previously
/// wrong* headers across the tree: that commit's mtime year (and so the
/// year it would feed into `git log`) does not represent a real edit to
/// the file content, so counting it would force every file forward to
/// the rewrite year regardless of whether it has actually been touched
/// since.
///
/// If filtering these commits out leaves no history at all (e.g. a file
/// that was *introduced* in one of the ignored commits), `file_years`
/// silently falls back to the unfiltered history so the file still gets
/// a sensible year.
const IGNORED_COMMITS: &[&str] = &[
    // "Fix all copyright headers to have correct time span" — bulk
    // rewrite of every file's header to its real first/last-edit span
    // on 2026-05-12. Not a content edit.
    "fb038a3897d933c604b369280d7ad55693970a05",
];

/// Operating mode for the `copyright` subcommand.
#[derive(Copy, Clone, Debug, Subcommand)]
pub enum Action {
    /// Report files whose header differs from git-derived years; exit non-zero
    /// if any do. This is the default when no subcommand is given.
    Check,
    /// Print a unified diff per file that would change; do not modify any
    /// files and always exit zero.
    DryRun,
    /// Rewrite files in place.
    Write,
}

/// Outcome of inspecting a single file.
#[derive(Debug)]
enum Plan {
    /// Header already matches the computed years.
    Unchanged,
    /// Header year span differs.
    UpdateYears { from: String, to: String },
    /// File has no recognised header; one will be inserted.
    InsertHeader { years: String },
}

/// Per-file result, including the rewritten content for `--dry-run` diffs.
struct Outcome {
    plan: Plan,
    original: String,
    rewritten: String,
}

/// Entry point invoked from `main.rs`.
pub fn run(mode: Action) -> anyhow::Result<()> {
    let repo_root = repo_root()?;
    debug!("repo root: {}", repo_root.display());

    let crate_roots = discover_crate_roots(&repo_root)?;
    if crate_roots.is_empty() {
        bail!(
            "no Cargo.toml files tracked by git under {}",
            repo_root.display()
        );
    }
    debug!("crate roots: {crate_roots:?}");

    let files = list_candidate_files(&repo_root, &crate_roots)?;
    info!("scanning {} file(s)", files.len());

    let mut changed = 0usize;
    let mut errors = 0usize;
    let mut inserted = 0usize;
    let mut updated = 0usize;
    let mut unchanged = 0usize;

    for rel in &files {
        let abs = repo_root.join(rel);

        match process_file(&repo_root, rel, &abs, mode) {
            Ok(Outcome {
                plan: Plan::Unchanged,
                ..
            }) => {
                unchanged += 1;
            }
            Ok(Outcome {
                plan: Plan::UpdateYears { from, to },
                original,
                rewritten,
            }) => {
                changed += 1;
                updated += 1;

                if matches!(mode, Action::DryRun) {
                    // Keep stdout clean so it can be piped straight to
                    // `git apply`. The per-file log line goes nowhere.
                    print_unified_diff(rel, &original, &rewritten);
                } else {
                    info!("{}: {from} -> {to}", rel.display());
                }
            }
            Ok(Outcome {
                plan: Plan::InsertHeader { years },
                original,
                rewritten,
            }) => {
                changed += 1;
                inserted += 1;

                if matches!(mode, Action::DryRun) {
                    print_unified_diff(rel, &original, &rewritten);
                } else {
                    info!("{}: insert header ({years})", rel.display());
                }
            }
            Err(err) => {
                errors += 1;
                error!("{}: {err:#}", rel.display());
            }
        }
    }

    info!(
        "summary: {} unchanged, {} updated, {} headers inserted, {} error(s)",
        unchanged, updated, inserted, errors,
    );

    if errors > 0 {
        bail!("{errors} file(s) could not be processed");
    }

    if matches!(mode, Action::Check) && changed > 0 {
        bail!("{changed} file(s) need copyright updates");
    }

    Ok(())
}

/// Decide what to do with a single file and (in `Write` mode) apply it.
fn process_file(repo_root: &Path, rel: &Path, abs: &Path, mode: Action) -> anyhow::Result<Outcome> {
    let (first_year, last_year) = file_years(repo_root, rel).context("computing git year span")?;
    let years = render_years(first_year, last_year);

    let original = fs::read_to_string(abs).with_context(|| format!("reading {}", abs.display()))?;

    let plan = decide(&original, &years)?;

    let rewritten = match &plan {
        Plan::Unchanged => original.clone(),
        Plan::UpdateYears { .. } => rewrite_existing(&original, &years)?,
        Plan::InsertHeader { years } => insert_header(&original, years),
    };

    if let Action::Write = mode {
        if !matches!(plan, Plan::Unchanged) {
            write_atomically(abs, &rewritten)?;
        }
    }

    Ok(Outcome {
        plan,
        original,
        rewritten,
    })
}

/// Inspect the file content and decide which `Plan` applies.
fn decide(content: &str, target_years: &str) -> anyhow::Result<Plan> {
    // Borrow a slice covering the first `HEADER_SCAN_LINES` lines instead of
    // allocating a new `String`.
    let head_end = content
        .match_indices('\n')
        .nth(HEADER_SCAN_LINES)
        .map(|(i, _)| i)
        .unwrap_or(content.len());
    let head = &content[..head_end];

    if !head.contains(HEADER_MARKER) {
        return Ok(Plan::InsertHeader {
            years: target_years.to_string(),
        });
    }

    let existing = extract_year_span(head)
        .ok_or_else(|| anyhow!("header present but year span could not be parsed"))?;

    if existing == target_years {
        Ok(Plan::Unchanged)
    } else {
        Ok(Plan::UpdateYears {
            from: existing,
            to: target_years.to_string(),
        })
    }
}

/// Pull the year span out of an existing copyright line. Accepts either
/// `2024` or `2020-2026`.
fn extract_year_span(head: &str) -> Option<String> {
    let line = head.lines().find(|l| l.contains(HEADER_MARKER))?;

    // Expected shape: `... Copyright (c) <YEARS> Project CHIP Authors ...`
    let (_, after) = line.split_once("Copyright (c) ")?;
    let (years, _) = after.split_once(" Project CHIP Authors")?;
    let years = years.trim();

    if !is_valid_year_span(years) {
        return None;
    }

    Some(years.to_string())
}

fn is_valid_year_span(s: &str) -> bool {
    let parts: Vec<&str> = s.split('-').collect();

    match parts.as_slice() {
        [a] => a.len() == 4 && a.chars().all(|c| c.is_ascii_digit()),
        [a, b] => {
            a.len() == 4
                && b.len() == 4
                && a.chars().all(|c| c.is_ascii_digit())
                && b.chars().all(|c| c.is_ascii_digit())
        }
        _ => false,
    }
}

/// Replace just the year span on the existing copyright line.
///
/// Iterates lines with `split_inclusive('\n')` so the original line terminator
/// (LF or CRLF) is preserved on each line we copy through. Once the header
/// line has been rewritten we stop scanning and append the rest of the file
/// as a single slice.
fn rewrite_existing(content: &str, target_years: &str) -> anyhow::Result<String> {
    let mut out = String::with_capacity(content.len());
    let mut consumed = 0usize;
    let mut replaced = false;

    for (idx, line) in content.split_inclusive('\n').enumerate() {
        if !replaced && idx < HEADER_SCAN_LINES && line.contains(HEADER_MARKER) {
            let (prefix, after) = line
                .split_once("Copyright (c) ")
                .ok_or_else(|| anyhow!("malformed copyright line: {line}"))?;
            let (_old_years, suffix) = after
                .split_once(" Project CHIP Authors")
                .ok_or_else(|| anyhow!("malformed copyright line: {line}"))?;

            out.push_str(prefix);
            out.push_str("Copyright (c) ");
            out.push_str(target_years);
            out.push_str(" Project CHIP Authors");
            out.push_str(suffix);

            consumed += line.len();
            replaced = true;
            break;
        }

        out.push_str(line);
        consumed += line.len();
    }

    if !replaced {
        bail!("copyright line not found while rewriting");
    }

    out.push_str(&content[consumed..]);

    Ok(out)
}

fn insert_header(content: &str, years: &str) -> String {
    let header = HEADER_TEMPLATE.replace("{YEARS}", years);

    let mut out = String::with_capacity(content.len() + header.len() + 1);
    out.push_str(&header);

    // One blank line between the header and existing content, unless the file
    // already starts with a blank line.
    if !content.starts_with('\n') {
        out.push('\n');
    }

    out.push_str(content);

    out
}

/// Print a tiny unified-diff for `--dry-run`. Our edits are always confined to
/// the top of the file, so we render a single hunk covering the differing
/// region plus 3 lines of context on each side — the same shape as `diff -u`.
/// Output goes to stdout so it interleaves cleanly with the log lines on
/// stderr.
fn print_unified_diff(path: &Path, before: &str, after: &str) {
    const CONTEXT: usize = 3;

    let a: Vec<&str> = before.split_inclusive('\n').collect();
    let b: Vec<&str> = after.split_inclusive('\n').collect();

    let mut first_diff = 0usize;
    while first_diff < a.len() && first_diff < b.len() && a[first_diff] == b[first_diff] {
        first_diff += 1;
    }

    let mut last_diff_a = a.len();
    let mut last_diff_b = b.len();
    while last_diff_a > first_diff
        && last_diff_b > first_diff
        && a[last_diff_a - 1] == b[last_diff_b - 1]
    {
        last_diff_a -= 1;
        last_diff_b -= 1;
    }

    let ctx_start = first_diff.saturating_sub(CONTEXT);
    let ctx_end_a = (last_diff_a + CONTEXT).min(a.len());
    let ctx_end_b = (last_diff_b + CONTEXT).min(b.len());

    let path_str = path.display();
    println!("--- a/{path_str}");
    println!("+++ b/{path_str}");
    println!(
        "@@ -{},{} +{},{} @@",
        ctx_start + 1,
        ctx_end_a - ctx_start,
        ctx_start + 1,
        ctx_end_b - ctx_start,
    );

    for line in &a[ctx_start..first_diff] {
        print!(" {line}");
    }
    for line in &a[first_diff..last_diff_a] {
        print!("-{line}");
    }
    for line in &b[first_diff..last_diff_b] {
        print!("+{line}");
    }
    for line in &a[last_diff_a..ctx_end_a] {
        print!(" {line}");
    }

    // Make sure the hunk ends with a newline so the next line starts clean.
    if !a
        .get(ctx_end_a.saturating_sub(1))
        .copied()
        .unwrap_or("")
        .ends_with('\n')
        && !b
            .get(ctx_end_b.saturating_sub(1))
            .copied()
            .unwrap_or("")
            .ends_with('\n')
    {
        println!();
    }
}

fn render_years(first: u32, last: u32) -> String {
    if first == last {
        format!("{first}")
    } else {
        format!("{first}-{last}")
    }
}

/// Atomic-ish file write: write to a sibling tempfile, then rename.
fn write_atomically(path: &Path, content: &str) -> anyhow::Result<()> {
    let tmp = path.with_extension(format!(
        "{}.copyright-tmp",
        path.extension().and_then(|s| s.to_str()).unwrap_or("rs")
    ));

    fs::write(&tmp, content).with_context(|| format!("writing {}", tmp.display()))?;
    fs::rename(&tmp, path)
        .with_context(|| format!("renaming {} -> {}", tmp.display(), path.display()))?;

    Ok(())
}

/// Resolve the workspace root via `git rev-parse --show-toplevel`.
fn repo_root() -> anyhow::Result<PathBuf> {
    let out = run_git(Path::new("."), &["rev-parse", "--show-toplevel"])?;

    Ok(PathBuf::from(out.trim()))
}

/// Find every directory containing a tracked `Cargo.toml`. Each such directory
/// is treated as a crate root for the purposes of the `src/`, `tests/`,
/// `build.rs` filter.
fn discover_crate_roots(repo_root: &Path) -> anyhow::Result<Vec<PathBuf>> {
    let out = run_git(repo_root, &["ls-files", "*Cargo.toml", "Cargo.toml"])?;

    let mut roots: Vec<PathBuf> = out
        .lines()
        .map(|l| {
            let p = Path::new(l.trim());
            p.parent().map(Path::to_path_buf).unwrap_or_default()
        })
        .collect();

    roots.sort();
    roots.dedup();

    Ok(roots)
}

/// Return the relative paths of every tracked `.rs` file that lives under
/// `<crate_root>/src/**`, `<crate_root>/tests/**`, or is exactly
/// `<crate_root>/build.rs`.
fn list_candidate_files(repo_root: &Path, crate_roots: &[PathBuf]) -> anyhow::Result<Vec<PathBuf>> {
    let out = run_git(repo_root, &["ls-files", "*.rs"])?;

    // Sort crate roots by descending path length so that a nested crate (e.g.
    // a future `rs-matter/foo`) is matched before its parent.
    let mut sorted_roots: Vec<&PathBuf> = crate_roots.iter().collect();
    sorted_roots.sort_by_key(|p| std::cmp::Reverse(p.as_os_str().len()));

    let mut files: Vec<PathBuf> = Vec::new();

    for line in out.lines() {
        let path = PathBuf::from(line.trim());
        if path.as_os_str().is_empty() {
            continue;
        }

        if let Some(crate_root) = sorted_roots.iter().find(|r| starts_with_dir(&path, r)) {
            let rel = strip_prefix_dir(&path, crate_root);

            if is_in_scope(&rel) {
                files.push(path);
            } else {
                debug!("skipping {} (outside src/tests/build.rs)", path.display());
            }
        } else {
            debug!("skipping {} (no enclosing crate)", path.display());
        }
    }

    files.sort();
    files.dedup();

    Ok(files)
}

/// `true` if `path` lies inside (or equals) `dir`. An empty `dir` represents
/// the workspace root and matches everything.
fn starts_with_dir(path: &Path, dir: &Path) -> bool {
    if dir.as_os_str().is_empty() {
        return true;
    }

    path.starts_with(dir)
}

fn strip_prefix_dir(path: &Path, dir: &Path) -> PathBuf {
    if dir.as_os_str().is_empty() {
        path.to_path_buf()
    } else {
        path.strip_prefix(dir).unwrap_or(path).to_path_buf()
    }
}

/// Crate-relative path is in scope iff it's `build.rs`, or under `src/` or
/// `tests/`.
fn is_in_scope(rel: &Path) -> bool {
    let mut comps = rel.components();

    match comps.next() {
        Some(std::path::Component::Normal(first)) => {
            if first == "build.rs" && comps.next().is_none() {
                return true;
            }

            if first == "src" || first == "tests" {
                return true;
            }

            false
        }
        _ => false,
    }
}

/// Compute (first_year, last_year) by walking the file's git history with
/// `--follow` (so renames are tracked).
///
/// `git log --follow` defaults to a 50% rename-similarity threshold, which is
/// loose enough that a newly-generated file can be mis-attributed to an
/// unrelated ancestor (e.g. a freshly-introduced proxy file getting glued onto
/// a 2022 commit from the original `matter`→`rs-matter` rename trail). We tell
/// git to require 85% similarity (`-M85%`) — high enough to filter spurious
/// matches, low enough to still catch real renames where a file gained a few
/// edits in the same commit it was renamed in. Per the user's stated
/// preference, when in doubt we err on the side of a wider year span (i.e.
/// keep following) rather than a narrower one.
///
/// Commits listed in [`IGNORED_COMMITS`] are filtered out of the history
/// before deriving the span (see the constant's doc comment for the
/// motivation). If filtering empties the history, we fall back to the
/// unfiltered list so the file still gets a year.
fn file_years(repo_root: &Path, rel: &Path) -> anyhow::Result<(u32, u32)> {
    let rel_str = rel.to_string_lossy().to_string();

    let out = run_git(
        repo_root,
        &[
            "log",
            "--follow",
            "-M85%",
            // `%H %ad` lets us drop commits by hash before parsing the
            // year. `%ad` with `--date=format:%Y` emits a 4-digit year.
            "--format=%H %ad",
            "--date=format:%Y",
            "--",
            &rel_str,
        ],
    )?;

    let entries: Vec<(&str, u32)> = out
        .lines()
        .filter_map(|l| {
            let (hash, year) = l.trim().split_once(' ')?;
            let year = year.trim().parse::<u32>().ok()?;
            Some((hash, year))
        })
        .collect();

    if entries.is_empty() {
        bail!("no git history for {}", rel.display());
    }

    let filtered: Vec<u32> = entries
        .iter()
        .filter(|(hash, _)| !IGNORED_COMMITS.iter().any(|ignored| *ignored == *hash))
        .map(|(_, year)| *year)
        .collect();

    // Defensive: if filtering removed everything (e.g. a file that
    // was *introduced* in an ignored commit), keep the unfiltered
    // history so the file still gets a sensible span.
    let years: Vec<u32> = if filtered.is_empty() {
        entries.into_iter().map(|(_, year)| year).collect()
    } else {
        filtered
    };

    // `git log` is newest-first.
    let last = *years.first().unwrap();
    let first = *years.last().unwrap();

    Ok((first, last))
}

fn run_git(cwd: &Path, args: &[&str]) -> anyhow::Result<String> {
    let output = Command::new("git")
        .current_dir(cwd)
        .args(args)
        .output()
        .with_context(|| format!("running `git {}`", args.join(" ")))?;

    if !output.status.success() {
        bail!(
            "`git {}` failed: {}",
            args.join(" "),
            String::from_utf8_lossy(&output.stderr).trim()
        );
    }

    String::from_utf8(output.stdout)
        .with_context(|| format!("decoding output of `git {}`", args.join(" ")))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn extract_year_span_works() {
        let head = " *    Copyright (c) 2020-2022 Project CHIP Authors\n";
        assert_eq!(extract_year_span(head).as_deref(), Some("2020-2022"));

        let head = " *    Copyright (c) 2024 Project CHIP Authors\n";
        assert_eq!(extract_year_span(head).as_deref(), Some("2024"));
    }

    #[test]
    fn rewrite_existing_replaces_only_year() {
        let src =
            "/*\n *\n *    Copyright (c) 2020-2022 Project CHIP Authors\n */\n\nfn main() {}\n";

        let out = rewrite_existing(src, "2020-2026").unwrap();

        assert!(out.contains("Copyright (c) 2020-2026 Project CHIP Authors"));
        assert!(out.ends_with("fn main() {}\n"));
    }

    #[test]
    fn rewrite_existing_preserves_crlf_line_endings() {
        let src = "/*\r\n *\r\n *    Copyright (c) 2020-2022 Project CHIP Authors\r\n */\r\n\r\nfn main() {}\r\n";

        let out = rewrite_existing(src, "2020-2026").unwrap();

        assert!(out.contains("Copyright (c) 2020-2026 Project CHIP Authors\r\n"));
        assert!(out.ends_with("fn main() {}\r\n"));
        assert!(!out.contains("Authors\n "));
    }

    #[test]
    fn rewrite_existing_preserves_missing_trailing_newline() {
        let src = "/*\n *    Copyright (c) 2020-2022 Project CHIP Authors\n */\nfn main() {}";

        let out = rewrite_existing(src, "2026").unwrap();

        assert!(out.ends_with("fn main() {}"));
        assert!(!out.ends_with('\n'));
    }

    #[test]
    fn insert_header_prepends() {
        let src = "fn main() {}\n";

        let out = insert_header(src, "2026");

        assert!(out.starts_with("/*"));
        assert!(out.contains("Copyright (c) 2026 Project CHIP Authors"));
        assert!(out.ends_with("fn main() {}\n"));
    }

    #[test]
    fn is_in_scope_filters_correctly() {
        assert!(is_in_scope(Path::new("src/lib.rs")));
        assert!(is_in_scope(Path::new("src/foo/bar.rs")));
        assert!(is_in_scope(Path::new("tests/it.rs")));
        assert!(is_in_scope(Path::new("build.rs")));
        assert!(!is_in_scope(Path::new("examples/x.rs")));
        assert!(!is_in_scope(Path::new("benches/b.rs")));
        assert!(!is_in_scope(Path::new("scripts/foo.rs")));
    }

    #[test]
    fn render_years_handles_single_and_span() {
        assert_eq!(render_years(2024, 2024), "2024");
        assert_eq!(render_years(2020, 2026), "2020-2026");
    }
}
