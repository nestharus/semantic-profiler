//! Bounded git rolling-window churn and co-change coupling analysis.

use crate::model::CoChangePair;
use std::collections::{BTreeMap, BTreeSet};
use std::io::Read;
use std::path::Path;
use std::process::{Command, Stdio};
use std::thread;
use std::time::{Duration, Instant};

#[cfg(windows)]
use std::os::windows::process::CommandExt;

#[cfg(windows)]
const CREATE_NO_WINDOW: u32 = 0x0800_0000;

/// Ignore massive bulk/rename commits touching more than this many files when
/// tallying pairwise co-change coupling so global sweeps do not pollute pairs.
const MAX_FILES_PER_COCHANGE_COMMIT: usize = 50;
const MAX_GIT_STDOUT_BYTES: u64 = 16 * 1024 * 1024;
const GIT_COMMAND_TIMEOUT: Duration = Duration::from_secs(30);

#[derive(Debug, Default)]
pub struct GitHistoryMetrics {
    pub available: bool,
    pub head_commit: Option<String>,
    pub commits_scanned: usize,
    pub churn_by_file: BTreeMap<String, usize>,
    pub partners_by_file: BTreeMap<String, usize>,
    pub co_change_pairs: Vec<CoChangePair>,
}

pub fn collect_git_history(
    repo_root: &Path,
    window: usize,
    known_files: &BTreeSet<String>,
) -> GitHistoryMetrics {
    let mut metrics = GitHistoryMetrics::default();
    if window == 0 {
        return metrics;
    }

    let Some(head) = run_git_capture(repo_root, &["rev-parse", "HEAD"]) else {
        return metrics;
    };
    let head = head.trim().to_string();
    if head.is_empty() {
        return metrics;
    }

    metrics.available = true;
    metrics.head_commit = Some(head);

    // Determine subdirectory prefix (empty at repo root, e.g. "tools/semantic-profiler/" in a subdir).
    let prefix = run_git_capture(repo_root, &["rev-parse", "--show-prefix"])
        .map(|s| s.trim().replace('\\', "/"))
        .unwrap_or_default();

    let limit_arg = format!("-n{window}");
    let Some(log_out) = run_git_capture(
        repo_root,
        &[
            "-c",
            "core.quotepath=false",
            "log",
            &limit_arg,
            "--no-renames",
            "--name-only",
            "--pretty=format:COMMIT:%H",
            "--",
            ".",
        ],
    ) else {
        return metrics;
    };

    let mut current_files: BTreeSet<String> = BTreeSet::new();
    let mut pair_counts: BTreeMap<(String, String), usize> = BTreeMap::new();
    let mut partner_sets: BTreeMap<String, BTreeSet<String>> = BTreeMap::new();

    for line in log_out.lines() {
        let trimmed = line.trim();
        if trimmed.starts_with("COMMIT:") {
            flush_commit(
                &current_files,
                &mut metrics.churn_by_file,
                &mut partner_sets,
                &mut pair_counts,
            );
            current_files.clear();
            metrics.commits_scanned += 1;
            continue;
        }
        if trimmed.is_empty() {
            continue;
        }
        let normalized = trimmed.replace('\\', "/");
        let relative = if prefix.is_empty() {
            normalized
        } else if let Some(stripped) = normalized.strip_prefix(&prefix) {
            stripped.to_string()
        } else {
            continue;
        };
        if known_files.contains(&relative) {
            current_files.insert(relative);
        }
    }
    flush_commit(
        &current_files,
        &mut metrics.churn_by_file,
        &mut partner_sets,
        &mut pair_counts,
    );

    for (file, partners) in partner_sets {
        metrics.partners_by_file.insert(file, partners.len());
    }

    let mut pairs: Vec<CoChangePair> = pair_counts
        .into_iter()
        .filter(|(_, count)| *count >= 2)
        .map(|((file_a, file_b), co_changes)| CoChangePair {
            file_a,
            file_b,
            co_changes,
        })
        .collect();
    pairs.sort_by(|a, b| {
        b.co_changes
            .cmp(&a.co_changes)
            .then_with(|| a.file_a.cmp(&b.file_a))
            .then_with(|| a.file_b.cmp(&b.file_b))
    });
    metrics.co_change_pairs = pairs;
    metrics
}

fn flush_commit(
    files: &BTreeSet<String>,
    churn: &mut BTreeMap<String, usize>,
    partners: &mut BTreeMap<String, BTreeSet<String>>,
    pair_counts: &mut BTreeMap<(String, String), usize>,
) {
    if files.is_empty() {
        return;
    }
    for f in files {
        *churn.entry(f.clone()).or_insert(0) += 1;
    }
    if files.len() < 2 || files.len() > MAX_FILES_PER_COCHANGE_COMMIT {
        return;
    }
    let ordered: Vec<&String> = files.iter().collect();
    for i in 0..ordered.len() {
        for j in (i + 1)..ordered.len() {
            let a = ordered[i];
            let b = ordered[j];
            partners.entry(a.clone()).or_default().insert(b.clone());
            partners.entry(b.clone()).or_default().insert(a.clone());
            *pair_counts.entry((a.clone(), b.clone())).or_insert(0) += 1;
        }
    }
}

fn run_git_capture(repo_root: &Path, args: &[&str]) -> Option<String> {
    run_git_capture_bounded(repo_root, args, GIT_COMMAND_TIMEOUT, MAX_GIT_STDOUT_BYTES)
}

fn run_git_capture_bounded(
    repo_root: &Path,
    args: &[&str],
    timeout: Duration,
    max_bytes: u64,
) -> Option<String> {
    let mut cmd = Command::new("git");
    cmd.env("GIT_TERMINAL_PROMPT", "0")
        .arg("-C")
        .arg(repo_root)
        .args(args)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::null());
    #[cfg(windows)]
    cmd.creation_flags(CREATE_NO_WINDOW);

    let mut child = cmd.spawn().ok()?;
    let stdout = child.stdout.take()?;

    let reader_handle = thread::spawn(move || {
        let mut buf = Vec::new();
        let mut limited = stdout.take(max_bytes.saturating_add(1));
        let _ = limited.read_to_end(&mut buf);
        buf
    });

    let deadline = Instant::now().checked_add(timeout);
    let status = loop {
        match child.try_wait() {
            Ok(Some(st)) => break Some(st),
            Ok(None) => {
                if deadline.is_some_and(|d| Instant::now() >= d) {
                    let _ = child.kill();
                    let _ = child.wait();
                    break None;
                }
                thread::sleep(Duration::from_millis(10));
            }
            Err(_) => {
                let _ = child.kill();
                let _ = child.wait();
                break None;
            }
        }
    };

    let mut buf = reader_handle.join().ok()?;
    let status = status?;
    if !status.success() {
        return None;
    }
    if (buf.len() as u64) > max_bytes {
        buf.truncate(max_bytes as usize);
    }
    Some(String::from_utf8_lossy(&buf).into_owned())
}
