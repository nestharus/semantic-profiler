//! Cross-repo ecosystem dependency, pin-skew, and blast-radius scanner.

pub mod manifests;
pub mod model;
pub mod topology;

use crate::ecosystem::manifests::{
    CargoDepSpec, CargoLockGitEntry, MAX_BASELINE_BYTES, MAX_MANIFEST_BYTES, ParsedDomainManifest,
    PythonDepSpec, git_url_repo_tail, normalize_git_url, normalize_python_name,
    parse_baseline_rollup, parse_cargo_lock, parse_cargo_toml, parse_domain_json,
    parse_pyproject_toml, read_utf8_safe,
};
use crate::ecosystem::model::{
    ECOSYSTEM_GRAPH_FORMAT, ECOSYSTEM_GRAPH_SCHEMA_VERSION, EcosystemEdge, EcosystemGraph,
    EcosystemRepoNode, EcosystemScanOptions, EcosystemSkipped, EcosystemSummary, PinSkewEntry,
    PublishedPackage, SemanticHealthRollup,
};
use crate::ecosystem::topology::{analyze_ecosystem_topology, build_impact_report};
use crate::model::FileRole;
use crate::safe_io::{is_reparse_or_symlink, reject_reparse_or_symlink_ancestors};
use crate::{ScanOptions, scan_repository};
use std::collections::{BTreeMap, BTreeSet, VecDeque};
use std::fs;
use std::io::Read;
use std::path::{Component, Path, PathBuf};
use std::process::{Command, Stdio};
use std::thread;
use std::time::{Duration, Instant};

#[cfg(windows)]
use std::os::windows::process::CommandExt;

#[cfg(windows)]
const CREATE_NO_WINDOW: u32 = 0x0800_0000;

const MAX_REPO_WALK_DEPTH: usize = 5;
const MAX_REPO_ENTRIES: usize = 5000;
const GIT_META_TIMEOUT: Duration = Duration::from_secs(10);
const MAX_GIT_META_BYTES: u64 = 64 * 1024;

const IGNORED_SUBDIRS: &[&str] = &[
    ".git",
    ".hg",
    ".svn",
    "target",
    "node_modules",
    ".venv",
    "venv",
    "__pycache__",
    ".pytest_cache",
    ".mypy_cache",
    ".ruff_cache",
    "dist",
    "build",
    "worktrees",
    "artifacts",
    "scratch",
    "scratchpads",
    "eval",
    "evals",
    "vendor",
    "var",
    "tmp",
    "runs",
    "logs",
    "fixtures",
    "testdata",
];

struct DiscoveredRepo {
    id: String,
    name: String,
    relative_path: String,
    abs_root: PathBuf,
    norm_abs_root: PathBuf,
    norm_root_key: String,
}

struct RepoExtracted {
    node: EcosystemRepoNode,
    norm_abs_root: PathBuf,
    norm_root_key: String,
    cargo_deps: Vec<(String, PathBuf, CargoDepSpec)>,
    cargo_locks: BTreeMap<String, (String, Vec<CargoLockGitEntry>)>,
    python_deps: Vec<(String, PathBuf, PythonDepSpec)>,
    domain_reqs: Vec<(String, String)>,
}

struct EcosystemIndex {
    by_norm_root: BTreeMap<String, usize>,
    by_git_url: BTreeMap<String, Vec<usize>>,
    by_git_tail: BTreeMap<String, Vec<usize>>,
    by_repo_id: BTreeMap<String, usize>,
    by_rust_crate: BTreeMap<String, Vec<usize>>,
    by_python_pkg: BTreeMap<String, Vec<usize>>,
    by_domain_id: BTreeMap<String, Vec<usize>>,
}

/// Scan a workspace root and/or explicit repository roots to produce the
/// canonical Tier 2 Cross-Repo Ecosystem Graph.
pub fn scan_ecosystem(options: &EcosystemScanOptions) -> Result<EcosystemGraph, String> {
    if options.workspace_root.is_none() && options.roots.is_empty() {
        return Err("ecosystem scan requires --workspace-root <dir> and/or --roots <dir>...".to_string());
    }

    let discovery_mode = match (&options.workspace_root, options.roots.is_empty()) {
        (Some(_), true) => "workspace_root".to_string(),
        (None, false) => "roots".to_string(),
        (Some(_), false) => "mixed".to_string(),
        (None, true) => unreachable!(),
    };

    let mut skipped: Vec<EcosystemSkipped> = Vec::new();
    let discovered = discover_repositories(options, &mut skipped)?;

    let mut extracted: Vec<RepoExtracted> = Vec::with_capacity(discovered.len());
    for repo in &discovered {
        extracted.push(extract_repo(repo, options.scan_repos, &mut skipped));
    }

    let index = build_ecosystem_index(&extracted);
    let (mut edges, mut pin_skew) = resolve_edges_and_skew(&extracted, &index);
    sort_and_dedup_edges(&mut edges);
    sort_and_dedup_pin_skew(&mut pin_skew);

    let mut nodes: Vec<EcosystemRepoNode> = extracted.into_iter().map(|e| e.node).collect();
    nodes.sort_by(|a, b| a.id.cmp(&b.id));

    let sccs = analyze_ecosystem_topology(&mut nodes, &edges);

    let impact = match &options.impact_target {
        Some(target) => Some(build_impact_report(target, &nodes, &edges, &sccs)?),
        None => None,
    };

    skipped.sort_by(|a, b| a.path.cmp(&b.path).then_with(|| a.reason.cmp(&b.reason)));
    skipped.dedup();

    let summary = build_summary(&nodes, &edges, &sccs, &pin_skew);

    Ok(EcosystemGraph {
        format: ECOSYSTEM_GRAPH_FORMAT.to_string(),
        schema_version: ECOSYSTEM_GRAPH_SCHEMA_VERSION,
        discovery_mode,
        summary,
        nodes,
        edges,
        sccs,
        pin_skew,
        impact,
        skipped,
    })
}

fn discover_repositories(
    options: &EcosystemScanOptions,
    skipped: &mut Vec<EcosystemSkipped>,
) -> Result<Vec<DiscoveredRepo>, String> {
    let mut raw_repos: Vec<(String, String, String, PathBuf)> = Vec::new();
    let mut seen_roots: BTreeSet<String> = BTreeSet::new();

    if let Some(ws_root) = &options.workspace_root {
        let ws_clean = reject_reparse_or_symlink_ancestors(ws_root, "workspace root")?;
        let ws_meta = fs::symlink_metadata(&ws_clean).map_err(|e| {
            format!("failed to stat workspace root {}: {e}", ws_clean.display())
        })?;
        if is_reparse_or_symlink(&ws_meta) {
            return Err(format!(
                "refusing symlink or reparse point workspace root: {}",
                ws_clean.display()
            ));
        }
        if !ws_meta.is_dir() {
            return Err(format!(
                "workspace root is not a directory: {}",
                ws_clean.display()
            ));
        }
        let mut child_entries: Vec<fs::DirEntry> = fs::read_dir(&ws_clean)
            .map_err(|e| format!("failed to read workspace root {}: {e}", ws_clean.display()))?
            .filter_map(Result::ok)
            .collect();
        child_entries.sort_by_key(|e| e.file_name());

        for entry in child_entries {
            let child_name = entry.file_name().to_string_lossy().to_string();
            let child_path = entry.path();
            let Ok(child_meta) = fs::symlink_metadata(&child_path) else {
                skipped.push(EcosystemSkipped {
                    path: child_name,
                    reason: "unreadable directory entry".to_string(),
                });
                continue;
            };
            if is_reparse_or_symlink(&child_meta) {
                skipped.push(EcosystemSkipped {
                    path: child_name,
                    reason: "symlink or reparse point skipped".to_string(),
                });
                continue;
            }
            if !child_meta.is_dir() || child_name.starts_with('.') {
                continue;
            }

            let trunk_path = child_path.join("trunk");
            if let Ok(trunk_meta) = fs::symlink_metadata(&trunk_path) {
                if is_reparse_or_symlink(&trunk_meta) {
                    skipped.push(EcosystemSkipped {
                        path: format!("{child_name}/trunk"),
                        reason: "symlink or reparse point skipped".to_string(),
                    });
                    continue;
                }
                if trunk_meta.is_dir() && looks_like_repo(&trunk_path) {
                    let norm_key = path_match_key(&normalize_abs_path(&trunk_path));
                    if seen_roots.insert(norm_key) {
                        raw_repos.push((
                            child_name.clone(),
                            child_name.clone(),
                            format!("{child_name}/trunk"),
                            trunk_path,
                        ));
                    }
                    continue;
                }
            }

            if looks_like_repo(&child_path) {
                let norm_key = path_match_key(&normalize_abs_path(&child_path));
                if seen_roots.insert(norm_key) {
                    raw_repos.push((
                        child_name.clone(),
                        child_name.clone(),
                        child_name,
                        child_path,
                    ));
                }
            }
        }
    }

    for root in &options.roots {
        let root_clean = reject_reparse_or_symlink_ancestors(root, "repo root")?;
        let meta = fs::symlink_metadata(&root_clean)
            .map_err(|e| format!("failed to stat repo root {}: {e}", root_clean.display()))?;
        if is_reparse_or_symlink(&meta) {
            return Err(format!(
                "refusing symlink or reparse point repo root: {}",
                root_clean.display()
            ));
        }
        if !meta.is_dir() {
            return Err(format!(
                "repo root is not a directory: {}",
                root_clean.display()
            ));
        }
        let norm_key = path_match_key(&normalize_abs_path(&root_clean));
        if seen_roots.insert(norm_key) {
            let name = logical_name_for_root(&root_clean);
            raw_repos.push((name.clone(), name.clone(), name, root_clean));
        }
    }

    raw_repos.sort_by(|a, b| a.0.cmp(&b.0).then_with(|| a.2.cmp(&b.2)));

    let mut used_ids: BTreeSet<String> = BTreeSet::new();
    let mut result = Vec::with_capacity(raw_repos.len());
    for (base_id, name, relative_path, abs_root) in raw_repos {
        let mut id = normalize_repo_id(&base_id);
        if !used_ids.insert(id.clone()) {
            let mut suffix = 2usize;
            loop {
                let candidate = format!("{id}-{suffix}");
                if used_ids.insert(candidate.clone()) {
                    id = candidate;
                    break;
                }
                suffix += 1;
            }
        }
        let norm_abs_root = normalize_abs_path(&abs_root);
        let norm_root_key = path_match_key(&norm_abs_root);
        result.push(DiscoveredRepo {
            id,
            name,
            relative_path,
            abs_root,
            norm_abs_root,
            norm_root_key,
        });
    }
    Ok(result)
}

fn logical_name_for_root(root: &Path) -> String {
    let norm = normalize_abs_path(root);
    let leaf = norm
        .file_name()
        .and_then(|s| s.to_str())
        .unwrap_or("repository");
    if leaf == "trunk"
        && let Some(parent) = norm.parent().and_then(|p| p.file_name()).and_then(|s| s.to_str())
        && !parent.is_empty()
    {
        return parent.to_string();
    }
    leaf.to_string()
}

fn normalize_repo_id(raw: &str) -> String {
    let trimmed = raw.trim();
    if trimmed.is_empty() {
        return "repository".to_string();
    }
    trimmed.replace(['\\', '/'], "-")
}

fn looks_like_repo(dir: &Path) -> bool {
    const MARKERS: &[&str] = &[
        ".git",
        "Cargo.toml",
        "pyproject.toml",
        "domain.json",
        "semantic-profile.json",
        "semantic-baseline.json",
    ];
    for marker in MARKERS {
        let p = dir.join(marker);
        if let Ok(meta) = fs::symlink_metadata(&p)
            && !is_reparse_or_symlink(&meta)
        {
            return true;
        }
    }
    false
}

fn extract_repo(
    repo: &DiscoveredRepo,
    live_scan: bool,
    skipped: &mut Vec<EcosystemSkipped>,
) -> RepoExtracted {
    let (git_head, git_branch, git_remote) = collect_repo_git_meta(&repo.abs_root);
    let has_semantic_profile = is_regular_non_symlink(&repo.abs_root.join("semantic-profile.json"));
    let baseline_path = repo.abs_root.join("semantic-baseline.json");
    let has_semantic_baseline = is_regular_non_symlink(&baseline_path);

    let semantic_health = if live_scan {
        compute_live_health(&repo.abs_root, &repo.id, skipped).or_else(|| {
            if has_semantic_baseline {
                load_baseline_health(&baseline_path, &repo.id, skipped)
            } else {
                None
            }
        })
    } else if has_semantic_baseline {
        load_baseline_health(&baseline_path, &repo.id, skipped)
    } else {
        None
    };

    let manifest_files = collect_repo_manifests(&repo.abs_root, &repo.id, skipped);
    let mut ecosystems: BTreeSet<String> = BTreeSet::new();
    let mut packages: Vec<PublishedPackage> = Vec::new();
    let mut cargo_deps: Vec<(String, PathBuf, CargoDepSpec)> = Vec::new();
    let mut cargo_locks: BTreeMap<String, (String, Vec<CargoLockGitEntry>)> = BTreeMap::new();
    let mut python_deps: Vec<(String, PathBuf, PythonDepSpec)> = Vec::new();
    let mut domain_reqs: Vec<(String, String)> = Vec::new();

    for (rel_posix, abs_path, kind) in manifest_files {
        let text = match read_utf8_safe(&abs_path, MAX_MANIFEST_BYTES) {
            Ok(t) => t,
            Err(reason) => {
                skipped.push(EcosystemSkipped {
                    path: format!("{}/{rel_posix}", repo.id),
                    reason,
                });
                continue;
            }
        };
        match kind {
            ManifestKind::CargoToml => {
                ecosystems.insert("rust".to_string());
                let parsed = parse_cargo_toml(&text);
                if let Some(pkg_name) = parsed.package_name {
                    packages.push(PublishedPackage {
                        ecosystem: "rust".to_string(),
                        name: pkg_name,
                        version: parsed.package_version,
                        manifest_path: rel_posix.clone(),
                    });
                }
                let manifest_dir = abs_path
                    .parent()
                    .map(normalize_abs_path)
                    .unwrap_or_else(|| repo.norm_abs_root.clone());
                for dep in parsed.dependencies {
                    if dep.workspace && dep.git.is_none() && dep.path.is_none() {
                        continue;
                    }
                    cargo_deps.push((rel_posix.clone(), manifest_dir.clone(), dep));
                }
            }
            ManifestKind::CargoLock => {
                let lock_dir = abs_path
                    .parent()
                    .map(normalize_abs_path)
                    .unwrap_or_else(|| repo.norm_abs_root.clone());
                let entries = parse_cargo_lock(&text);
                cargo_locks.insert(path_match_key(&lock_dir), (rel_posix, entries));
            }
            ManifestKind::PyprojectToml => {
                ecosystems.insert("python".to_string());
                let parsed = parse_pyproject_toml(&text);
                if let Some(pkg_name) = parsed.package_name {
                    packages.push(PublishedPackage {
                        ecosystem: "python".to_string(),
                        name: pkg_name,
                        version: parsed.package_version,
                        manifest_path: rel_posix.clone(),
                    });
                }
                let manifest_dir = abs_path
                    .parent()
                    .map(normalize_abs_path)
                    .unwrap_or_else(|| repo.norm_abs_root.clone());
                for dep in parsed.dependencies {
                    python_deps.push((rel_posix.clone(), manifest_dir.clone(), dep));
                }
            }
            ManifestKind::DomainJson => match parse_domain_json(&text) {
                Ok(Some(ParsedDomainManifest {
                    id,
                    version,
                    requires_domains,
                })) => {
                    ecosystems.insert("domain".to_string());
                    packages.push(PublishedPackage {
                        ecosystem: "domain".to_string(),
                        name: id,
                        version,
                        manifest_path: rel_posix.clone(),
                    });
                    for req in requires_domains {
                        domain_reqs.push((rel_posix.clone(), req));
                    }
                }
                Ok(None) => {}
                Err(reason) => {
                    skipped.push(EcosystemSkipped {
                        path: format!("{}/{rel_posix}", repo.id),
                        reason,
                    });
                }
            },
        }
    }

    packages.sort();
    packages.dedup();

    RepoExtracted {
        node: EcosystemRepoNode {
            id: repo.id.clone(),
            name: repo.name.clone(),
            relative_path: repo.relative_path.clone(),
            git_head,
            git_branch,
            git_remote,
            ecosystems: ecosystems.into_iter().collect(),
            packages,
            has_semantic_profile,
            has_semantic_baseline,
            semantic_health,
            fan_in: 0,
            fan_out: 0,
            scc_id: None,
            transitive_dependents: Vec::new(),
            transitive_dependent_count: 0,
        },
        norm_abs_root: repo.norm_abs_root.clone(),
        norm_root_key: repo.norm_root_key.clone(),
        cargo_deps,
        cargo_locks,
        python_deps,
        domain_reqs,
    }
}

#[derive(Debug, Clone, Copy)]
enum ManifestKind {
    CargoToml,
    CargoLock,
    PyprojectToml,
    DomainJson,
}

fn collect_repo_manifests(
    repo_root: &Path,
    repo_id: &str,
    skipped: &mut Vec<EcosystemSkipped>,
) -> Vec<(String, PathBuf, ManifestKind)> {
    let mut found: Vec<(String, PathBuf, ManifestKind)> = Vec::new();
    let mut excluded_patterns: Vec<String> = Vec::new();
    let mut visited_entries = 0usize;
    let mut queue: VecDeque<(PathBuf, usize)> = VecDeque::new();
    queue.push_back((repo_root.to_path_buf(), 0));

    while let Some((dir, depth)) = queue.pop_front() {
        let Ok(read_dir) = fs::read_dir(&dir) else {
            continue;
        };
        let mut entries: Vec<fs::DirEntry> = read_dir.filter_map(Result::ok).collect();
        entries.sort_by_key(|e| e.file_name());

        // Inspect Cargo.toml in this directory first so `[workspace] exclude` prunes sibling subdirs.
        let dir_rel = if dir == repo_root {
            String::new()
        } else {
            rel_posix(repo_root, &dir)
        };
        let cargo_here = dir.join("Cargo.toml");
        if is_regular_non_symlink(&cargo_here)
            && let Ok(text) = read_utf8_safe(&cargo_here, MAX_MANIFEST_BYTES)
        {
            let parsed = parse_cargo_toml(&text);
            for pat in parsed.workspace_exclude {
                let norm_pat = pat.trim().replace('\\', "/").trim_matches('/').to_string();
                if norm_pat.is_empty() {
                    continue;
                }
                let scoped = if dir_rel.is_empty() {
                    norm_pat
                } else {
                    format!("{dir_rel}/{norm_pat}")
                };
                excluded_patterns.push(scoped);
            }
        }

        for entry in entries {
            let fname = entry.file_name().to_string_lossy().to_string();
            let lower_fname = fname.to_ascii_lowercase();
            let path = entry.path();
            let rel = rel_posix(repo_root, &path);
            let Ok(meta) = fs::symlink_metadata(&path) else {
                continue;
            };
            if is_reparse_or_symlink(&meta) {
                if matches!(
                    fname.as_str(),
                    "Cargo.toml" | "Cargo.lock" | "pyproject.toml" | "domain.json"
                ) || depth == 0
                {
                    skipped.push(EcosystemSkipped {
                        path: format!("{repo_id}/{rel}"),
                        reason: "symlink or reparse point skipped".to_string(),
                    });
                }
                continue;
            }
            if meta.is_dir() {
                if fname.starts_with('.')
                    || IGNORED_SUBDIRS.contains(&lower_fname.as_str())
                    || matches_workspace_exclude(&rel, &excluded_patterns)
                {
                    continue;
                }
                visited_entries += 1;
                if visited_entries > MAX_REPO_ENTRIES {
                    skipped.push(EcosystemSkipped {
                        path: repo_id.to_string(),
                        reason: format!("manifest scan truncated after {MAX_REPO_ENTRIES} entries"),
                    });
                    found.sort_by(|a, b| a.0.cmp(&b.0));
                    return found;
                }
                if depth < MAX_REPO_WALK_DEPTH {
                    queue.push_back((path, depth + 1));
                }
                continue;
            }
            visited_entries += 1;
            if visited_entries > MAX_REPO_ENTRIES {
                skipped.push(EcosystemSkipped {
                    path: repo_id.to_string(),
                    reason: format!("manifest scan truncated after {MAX_REPO_ENTRIES} entries"),
                });
                found.sort_by(|a, b| a.0.cmp(&b.0));
                return found;
            }
            if !meta.is_file() {
                continue;
            }
            let kind = match fname.as_str() {
                "Cargo.toml" => Some(ManifestKind::CargoToml),
                "Cargo.lock" => Some(ManifestKind::CargoLock),
                "pyproject.toml" => Some(ManifestKind::PyprojectToml),
                "domain.json" => Some(ManifestKind::DomainJson),
                _ => None,
            };
            if let Some(k) = kind {
                found.push((rel, path, k));
            }
        }
    }

    found.sort_by(|a, b| a.0.cmp(&b.0));
    found
}

fn matches_workspace_exclude(rel: &str, patterns: &[String]) -> bool {
    let rel_norm = rel.trim_matches('/');
    for pat in patterns {
        if rel_norm == pat
            || rel_norm
                .strip_prefix(pat.as_str())
                .is_some_and(|rest| rest.starts_with('/'))
        {
            return true;
        }
        if pat.contains('*') && simple_glob_match(pat, rel_norm) {
            return true;
        }
    }
    false
}

fn simple_glob_match(pattern: &str, text: &str) -> bool {
    let p: Vec<char> = pattern.chars().collect();
    let t: Vec<char> = text.chars().collect();
    let (mut pi, mut ti) = (0usize, 0usize);
    let mut star_pi: Option<usize> = None;
    let mut star_ti = 0usize;
    while ti < t.len() {
        if pi < p.len() && (p[pi] == '?' || p[pi] == t[ti]) {
            pi += 1;
            ti += 1;
        } else if pi < p.len() && p[pi] == '*' {
            star_pi = Some(pi);
            pi += 1;
            star_ti = ti;
        } else if let Some(sp) = star_pi {
            pi = sp + 1;
            star_ti += 1;
            ti = star_ti;
        } else {
            return false;
        }
    }
    while pi < p.len() && p[pi] == '*' {
        pi += 1;
    }
    pi == p.len()
}

fn load_baseline_health(
    baseline_path: &Path,
    repo_id: &str,
    skipped: &mut Vec<EcosystemSkipped>,
) -> Option<SemanticHealthRollup> {
    let text = match read_utf8_safe(baseline_path, MAX_BASELINE_BYTES) {
        Ok(t) => t,
        Err(reason) => {
            skipped.push(EcosystemSkipped {
                path: format!("{repo_id}/semantic-baseline.json"),
                reason,
            });
            return None;
        }
    };
    match parse_baseline_rollup(&text) {
        Ok(rollup) => Some(rollup),
        Err(reason) => {
            skipped.push(EcosystemSkipped {
                path: format!("{repo_id}/semantic-baseline.json"),
                reason,
            });
            None
        }
    }
}

fn compute_live_health(
    repo_root: &Path,
    repo_id: &str,
    skipped: &mut Vec<EcosystemSkipped>,
) -> Option<SemanticHealthRollup> {
    let opts = ScanOptions {
        git_window: 0,
        profile_path: None,
        include_evals: false,
    };
    let snap = match scan_repository(repo_root, &opts) {
        Ok(s) => s,
        Err(err) => {
            skipped.push(EcosystemSkipped {
                path: repo_id.to_string(),
                reason: format!("live scan failed: {err}"),
            });
            return None;
        }
    };
    let top_hotspot_path = snap
        .files
        .iter()
        .filter(|f| f.role == FileRole::Production)
        .max_by(|a, b| {
            a.hotspot_score
                .total_cmp(&b.hotspot_score)
                .then_with(|| b.path.cmp(&a.path))
        })
        .map(|f| f.path.clone());
    Some(SemanticHealthRollup {
        source: "live_scan".to_string(),
        commit: snap.commit,
        prod_loc: snap.summary.prod_loc,
        scc_count: snap.summary.scc_count,
        top_hotspot_score: snap.summary.top_hotspot_score,
        top_hotspot_path,
        bypass_count: snap.summary.bypass_count,
        smeared_write_count: snap.summary.smeared_write_count,
        blanket_suppressions: snap.summary.blanket_suppressions,
    })
}

fn build_ecosystem_index(repos: &[RepoExtracted]) -> EcosystemIndex {
    let mut idx = EcosystemIndex {
        by_norm_root: BTreeMap::new(),
        by_git_url: BTreeMap::new(),
        by_git_tail: BTreeMap::new(),
        by_repo_id: BTreeMap::new(),
        by_rust_crate: BTreeMap::new(),
        by_python_pkg: BTreeMap::new(),
        by_domain_id: BTreeMap::new(),
    };

    for (i, repo) in repos.iter().enumerate() {
        idx.by_norm_root.insert(repo.norm_root_key.clone(), i);
        idx.by_repo_id.insert(repo.node.id.to_ascii_lowercase(), i);
        if let Some(remote) = &repo.node.git_remote {
            idx.by_git_url.entry(remote.clone()).or_default().push(i);
            if let Some(tail) = git_url_repo_tail(remote) {
                idx.by_git_tail.entry(tail.to_string()).or_default().push(i);
            }
        }
        idx.by_git_tail
            .entry(repo.node.name.to_ascii_lowercase())
            .or_default()
            .push(i);

        for pkg in &repo.node.packages {
            match pkg.ecosystem.as_str() {
                "rust" => idx.by_rust_crate.entry(pkg.name.clone()).or_default().push(i),
                "python" => idx
                    .by_python_pkg
                    .entry(normalize_python_name(&pkg.name))
                    .or_default()
                    .push(i),
                "domain" => idx.by_domain_id.entry(pkg.name.clone()).or_default().push(i),
                _ => {}
            }
        }
    }

    for v in idx
        .by_git_url
        .values_mut()
        .chain(idx.by_git_tail.values_mut())
        .chain(idx.by_rust_crate.values_mut())
        .chain(idx.by_python_pkg.values_mut())
        .chain(idx.by_domain_id.values_mut())
    {
        v.sort_unstable();
        v.dedup();
    }
    idx
}

fn resolve_edges_and_skew(
    repos: &[RepoExtracted],
    index: &EcosystemIndex,
) -> (Vec<EcosystemEdge>, Vec<PinSkewEntry>) {
    let mut edges = Vec::new();
    let mut pin_skew = Vec::new();

    for (src_idx, repo) in repos.iter().enumerate() {
        resolve_cargo_edges(src_idx, repo, repos, index, &mut edges, &mut pin_skew);
        resolve_python_edges(src_idx, repo, repos, index, &mut edges, &mut pin_skew);
        resolve_domain_edges(src_idx, repo, repos, index, &mut edges);
    }
    (edges, pin_skew)
}

fn resolve_cargo_edges(
    src_idx: usize,
    repo: &RepoExtracted,
    repos: &[RepoExtracted],
    index: &EcosystemIndex,
    edges: &mut Vec<EcosystemEdge>,
    pin_skew: &mut Vec<PinSkewEntry>,
) {
    for (manifest_rel, manifest_dir, dep) in &repo.cargo_deps {
        if let Some(rel_path) = &dep.path {
            let resolved_key = path_match_key(&manifest_dir.join(rel_path));
            if !path_key_contains(&repo.norm_root_key, &resolved_key)
                && let Some(dst_idx) = find_repo_containing_path(&resolved_key, index)
                && dst_idx != src_idx
            {
                edges.push(EcosystemEdge {
                    from: repo.node.id.clone(),
                    to: repos[dst_idx].node.id.clone(),
                    ecosystem: "rust".to_string(),
                    kind: "cargo_path".to_string(),
                    dependency_section: Some(dep.section.clone()),
                    package_name: dep.package_name.clone(),
                    manifest_path: manifest_rel.clone(),
                    declared_spec: Some(rel_path.clone()),
                    pinned_rev: None,
                    pinned_branch: None,
                    pinned_tag: None,
                    locked_rev: None,
                    target_head: repos[dst_idx].node.git_head.clone(),
                    pin_skew: false,
                });
            }
        }

        if let Some(git_url) = &dep.git {
            let norm_url = normalize_git_url(git_url);
            let Some(dst_idx) =
                resolve_git_target(src_idx, &norm_url, &dep.package_name, repos, index, true)
            else {
                continue;
            };
            let lock_match = find_cargo_lock_match(
                manifest_dir,
                &repo.norm_abs_root,
                &repo.cargo_locks,
                dep,
                &norm_url,
            );
            let (lockfile_path, locked_rev) = match lock_match {
                Some((lpath, entry)) => (Some(lpath), Some(entry.resolved_sha.clone())),
                None => (None, None),
            };
            let target_head = repos[dst_idx].node.git_head.clone();
            let skew_eval = evaluate_pin_skew(
                dep.rev.as_deref(),
                locked_rev.as_deref(),
                target_head.as_deref(),
                "cargo_toml",
            );
            let is_skew = skew_eval.is_some();
            if let Some((resolved_sha, skew_source)) = skew_eval
                && let Some(head_sha) = &target_head
            {
                pin_skew.push(PinSkewEntry {
                    from_repo: repo.node.id.clone(),
                    to_repo: repos[dst_idx].node.id.clone(),
                    package_name: dep.package_name.clone(),
                    manifest_path: manifest_rel.clone(),
                    lockfile_path,
                    declared_rev: dep.rev.clone(),
                    declared_branch: dep.branch.clone(),
                    declared_tag: dep.tag.clone(),
                    resolved_sha,
                    target_head_sha: head_sha.clone(),
                    skew_source,
                });
            }

            edges.push(EcosystemEdge {
                from: repo.node.id.clone(),
                to: repos[dst_idx].node.id.clone(),
                ecosystem: "rust".to_string(),
                kind: "cargo_git".to_string(),
                dependency_section: Some(dep.section.clone()),
                package_name: dep.package_name.clone(),
                manifest_path: manifest_rel.clone(),
                declared_spec: Some(git_url.clone()),
                pinned_rev: dep.rev.clone(),
                pinned_branch: dep.branch.clone(),
                pinned_tag: dep.tag.clone(),
                locked_rev,
                target_head,
                pin_skew: is_skew,
            });
        }
    }
}

fn resolve_python_edges(
    src_idx: usize,
    repo: &RepoExtracted,
    repos: &[RepoExtracted],
    index: &EcosystemIndex,
    edges: &mut Vec<EcosystemEdge>,
    pin_skew: &mut Vec<PinSkewEntry>,
) {
    for (manifest_rel, manifest_dir, dep) in &repo.python_deps {
        let mut resolved_by_path = false;
        if let Some(rel_path) = &dep.path {
            let resolved_key = path_match_key(&manifest_dir.join(rel_path));
            if !path_key_contains(&repo.norm_root_key, &resolved_key)
                && let Some(dst_idx) = find_repo_containing_path(&resolved_key, index)
                && dst_idx != src_idx
            {
                resolved_by_path = true;
                edges.push(EcosystemEdge {
                    from: repo.node.id.clone(),
                    to: repos[dst_idx].node.id.clone(),
                    ecosystem: "python".to_string(),
                    kind: "python_path".to_string(),
                    dependency_section: Some(dep.section.clone()),
                    package_name: dep.name.clone(),
                    manifest_path: manifest_rel.clone(),
                    declared_spec: Some(rel_path.clone()),
                    pinned_rev: None,
                    pinned_branch: None,
                    pinned_tag: None,
                    locked_rev: None,
                    target_head: repos[dst_idx].node.git_head.clone(),
                    pin_skew: false,
                });
            }
        }
        if resolved_by_path && dep.git_url.is_none() {
            continue;
        }

        let mut targets: Vec<usize> = if let Some(git_url) = &dep.git_url {
            let norm = normalize_git_url(git_url);
            resolve_git_target(src_idx, &norm, &dep.name, repos, index, false)
                .into_iter()
                .collect()
        } else {
            index
                .by_python_pkg
                .get(&dep.normalized_name)
                .cloned()
                .unwrap_or_default()
                .into_iter()
                .filter(|&i| i != src_idx)
                .collect()
        };
        if targets.is_empty() && dep.git_url.is_some() {
            let norm = normalize_git_url(dep.git_url.as_deref().unwrap_or_default());
            targets = index
                .by_python_pkg
                .get(&dep.normalized_name)
                .cloned()
                .unwrap_or_default()
                .into_iter()
                .filter(|&i| i != src_idx && remote_compatible(i, &norm, repos))
                .collect();
        }

        for dst_idx in targets {
            let target_head = repos[dst_idx].node.git_head.clone();
            let skew_eval = evaluate_pin_skew(
                dep.git_rev.as_deref(),
                None,
                target_head.as_deref(),
                "pyproject_toml",
            );
            let is_skew = skew_eval.is_some();
            if let Some((resolved_sha, skew_source)) = skew_eval
                && let Some(head_sha) = &target_head
            {
                pin_skew.push(PinSkewEntry {
                    from_repo: repo.node.id.clone(),
                    to_repo: repos[dst_idx].node.id.clone(),
                    package_name: dep.name.clone(),
                    manifest_path: manifest_rel.clone(),
                    lockfile_path: None,
                    declared_rev: dep.git_rev.clone(),
                    declared_branch: None,
                    declared_tag: None,
                    resolved_sha,
                    target_head_sha: head_sha.clone(),
                    skew_source,
                });
            }

            edges.push(EcosystemEdge {
                from: repo.node.id.clone(),
                to: repos[dst_idx].node.id.clone(),
                ecosystem: "python".to_string(),
                kind: if dep.is_optional {
                    "python_optional_dep".to_string()
                } else {
                    "python_dep".to_string()
                },
                dependency_section: Some(dep.section.clone()),
                package_name: dep.name.clone(),
                manifest_path: manifest_rel.clone(),
                declared_spec: Some(dep.raw_spec.clone()),
                pinned_rev: dep.git_rev.clone(),
                pinned_branch: None,
                pinned_tag: None,
                locked_rev: None,
                target_head,
                pin_skew: is_skew,
            });
        }
    }
}

fn resolve_domain_edges(
    src_idx: usize,
    repo: &RepoExtracted,
    repos: &[RepoExtracted],
    index: &EcosystemIndex,
    edges: &mut Vec<EcosystemEdge>,
) {
    for (manifest_rel, req_domain) in &repo.domain_reqs {
        let Some(targets) = index.by_domain_id.get(req_domain) else {
            continue;
        };
        for &dst_idx in targets {
            if dst_idx == src_idx {
                continue;
            }
            edges.push(EcosystemEdge {
                from: repo.node.id.clone(),
                to: repos[dst_idx].node.id.clone(),
                ecosystem: "domain".to_string(),
                kind: "domain_requires".to_string(),
                dependency_section: Some("requires_domains".to_string()),
                package_name: req_domain.clone(),
                manifest_path: manifest_rel.clone(),
                declared_spec: Some(req_domain.clone()),
                pinned_rev: None,
                pinned_branch: None,
                pinned_tag: None,
                locked_rev: None,
                target_head: repos[dst_idx].node.git_head.clone(),
                pin_skew: false,
            });
        }
    }
}

fn remote_compatible(candidate_idx: usize, norm_url: &str, repos: &[RepoExtracted]) -> bool {
    match repos[candidate_idx].node.git_remote.as_deref() {
        Some(known) => known == norm_url,
        None => true,
    }
}

fn resolve_git_target(
    src_idx: usize,
    norm_url: &str,
    package_name: &str,
    repos: &[RepoExtracted],
    index: &EcosystemIndex,
    allow_rust_crate_fallback: bool,
) -> Option<usize> {
    if let Some(candidates) = index.by_git_url.get(norm_url) {
        let non_self: Vec<usize> = candidates.iter().copied().filter(|&i| i != src_idx).collect();
        if non_self.len() == 1 {
            return Some(non_self[0]);
        }
        if allow_rust_crate_fallback
            && let Some(by_crate) = index.by_rust_crate.get(package_name)
            && let Some(&matched) = non_self.iter().find(|i| by_crate.contains(i))
        {
            return Some(matched);
        }
    }

    if let Some(tail) = git_url_repo_tail(norm_url) {
        if let Some(&direct) = index.by_repo_id.get(tail)
            && direct != src_idx
            && remote_compatible(direct, norm_url, repos)
        {
            return Some(direct);
        }
        if let Some(candidates) = index.by_git_tail.get(tail) {
            let compatible: Vec<usize> = candidates
                .iter()
                .copied()
                .filter(|&i| i != src_idx && remote_compatible(i, norm_url, repos))
                .collect();
            if compatible.len() == 1 {
                return Some(compatible[0]);
            }
        }
    }

    if allow_rust_crate_fallback
        && let Some(candidates) = index.by_rust_crate.get(package_name)
    {
        let compatible: Vec<usize> = candidates
            .iter()
            .copied()
            .filter(|&i| i != src_idx && remote_compatible(i, norm_url, repos))
            .collect();
        if compatible.len() == 1 {
            return Some(compatible[0]);
        }
    }
    None
}

fn find_cargo_lock_match<'a>(
    manifest_dir: &Path,
    repo_root: &Path,
    locks: &'a BTreeMap<String, (String, Vec<CargoLockGitEntry>)>,
    dep: &CargoDepSpec,
    norm_git_url: &str,
) -> Option<(String, &'a CargoLockGitEntry)> {
    let repo_root_key = path_match_key(repo_root);
    let mut cur = Some(manifest_dir);
    while let Some(dir) = cur {
        let dir_key = path_match_key(dir);
        if let Some((lock_rel, entries)) = locks.get(&dir_key) {
            let candidates: Vec<&CargoLockGitEntry> = entries
                .iter()
                .filter(|e| e.name == dep.package_name && e.normalized_git_url == norm_git_url)
                .collect();
            if !candidates.is_empty() {
                if let Some(rev) = dep.rev.as_deref() {
                    let rev_lower = rev.trim().to_ascii_lowercase();
                    if let Some(&exact) = candidates
                        .iter()
                        .find(|e| sha_matches(&rev_lower, &e.resolved_sha))
                    {
                        return Some((lock_rel.clone(), exact));
                    }
                }
                if let Some(branch) = dep.branch.as_deref() {
                    let needle = format!("branch={branch}");
                    if let Some(&exact) = candidates
                        .iter()
                        .find(|e| e.query_ref.as_deref() == Some(needle.as_str()))
                    {
                        return Some((lock_rel.clone(), exact));
                    }
                }
                if let Some(tag) = dep.tag.as_deref() {
                    let needle = format!("tag={tag}");
                    if let Some(&exact) = candidates
                        .iter()
                        .find(|e| e.query_ref.as_deref() == Some(needle.as_str()))
                    {
                        return Some((lock_rel.clone(), exact));
                    }
                }
                return Some((lock_rel.clone(), candidates[0]));
            }
        }
        if dir_key == repo_root_key {
            break;
        }
        cur = dir.parent();
    }
    None
}

fn evaluate_pin_skew(
    declared_rev: Option<&str>,
    locked_rev: Option<&str>,
    target_head: Option<&str>,
    manifest_source: &str,
) -> Option<(String, String)> {
    let head = target_head?.trim().to_ascii_lowercase();
    if !looks_like_hex_sha(&head) {
        return None;
    }

    let lock_hex = locked_rev
        .map(|s| s.trim().to_ascii_lowercase())
        .filter(|s| looks_like_hex_sha(s));
    let decl_hex = declared_rev
        .map(|s| s.trim().to_ascii_lowercase())
        .filter(|s| looks_like_hex_sha(s));

    let lock_skew = lock_hex.as_deref().is_some_and(|l| !sha_matches(l, &head));
    let decl_skew = decl_hex.as_deref().is_some_and(|d| !sha_matches(d, &head));

    match (lock_skew, decl_skew) {
        (true, true) => Some((lock_hex.unwrap_or_default(), "both".to_string())),
        (true, false) => Some((lock_hex.unwrap_or_default(), "cargo_lock".to_string())),
        (false, true) => Some((decl_hex.unwrap_or_default(), manifest_source.to_string())),
        (false, false) => None,
    }
}

fn looks_like_hex_sha(s: &str) -> bool {
    s.len() >= 7 && s.len() <= 64 && s.bytes().all(|b| b.is_ascii_hexdigit())
}

fn sha_matches(pinned: &str, head: &str) -> bool {
    head.starts_with(pinned) || pinned.starts_with(head)
}

fn find_repo_containing_path(path_key: &str, index: &EcosystemIndex) -> Option<usize> {
    let mut best: Option<(usize, usize)> = None;
    for (root_key, &repo_idx) in &index.by_norm_root {
        if path_key_contains(root_key, path_key) {
            let depth = root_key.len();
            if best.is_none_or(|(best_depth, _)| depth > best_depth) {
                best = Some((depth, repo_idx));
            }
        }
    }
    best.map(|(_, idx)| idx)
}

fn build_summary(
    nodes: &[EcosystemRepoNode],
    edges: &[EcosystemEdge],
    sccs: &[crate::ecosystem::model::EcosystemScc],
    pin_skew: &[PinSkewEntry],
) -> EcosystemSummary {
    EcosystemSummary {
        repo_count: nodes.len(),
        edge_count: edges.len(),
        scc_count: sccs.len(),
        pin_skew_count: pin_skew.len(),
        rust_repo_count: nodes
            .iter()
            .filter(|n| n.ecosystems.iter().any(|e| e == "rust"))
            .count(),
        python_repo_count: nodes
            .iter()
            .filter(|n| n.ecosystems.iter().any(|e| e == "python"))
            .count(),
        domain_repo_count: nodes
            .iter()
            .filter(|n| n.ecosystems.iter().any(|e| e == "domain"))
            .count(),
        repos_with_profile: nodes.iter().filter(|n| n.has_semantic_profile).count(),
        repos_with_baseline: nodes.iter().filter(|n| n.has_semantic_baseline).count(),
    }
}

fn sort_and_dedup_edges(edges: &mut Vec<EcosystemEdge>) {
    edges.sort_by(|a, b| {
        a.from
            .cmp(&b.from)
            .then_with(|| a.to.cmp(&b.to))
            .then_with(|| a.ecosystem.cmp(&b.ecosystem))
            .then_with(|| a.kind.cmp(&b.kind))
            .then_with(|| a.package_name.cmp(&b.package_name))
            .then_with(|| a.manifest_path.cmp(&b.manifest_path))
            .then_with(|| a.dependency_section.cmp(&b.dependency_section))
            .then_with(|| a.declared_spec.cmp(&b.declared_spec))
            .then_with(|| a.pinned_rev.cmp(&b.pinned_rev))
            .then_with(|| a.pinned_branch.cmp(&b.pinned_branch))
            .then_with(|| a.pinned_tag.cmp(&b.pinned_tag))
            .then_with(|| a.locked_rev.cmp(&b.locked_rev))
            .then_with(|| a.target_head.cmp(&b.target_head))
            .then_with(|| a.pin_skew.cmp(&b.pin_skew))
    });
    edges.dedup();
}

fn sort_and_dedup_pin_skew(entries: &mut Vec<PinSkewEntry>) {
    entries.sort_by(|a, b| {
        a.from_repo
            .cmp(&b.from_repo)
            .then_with(|| a.to_repo.cmp(&b.to_repo))
            .then_with(|| a.package_name.cmp(&b.package_name))
            .then_with(|| a.manifest_path.cmp(&b.manifest_path))
            .then_with(|| a.lockfile_path.cmp(&b.lockfile_path))
            .then_with(|| a.declared_rev.cmp(&b.declared_rev))
            .then_with(|| a.declared_branch.cmp(&b.declared_branch))
            .then_with(|| a.declared_tag.cmp(&b.declared_tag))
            .then_with(|| a.resolved_sha.cmp(&b.resolved_sha))
            .then_with(|| a.target_head_sha.cmp(&b.target_head_sha))
            .then_with(|| a.skew_source.cmp(&b.skew_source))
    });
    entries.dedup();
}

fn collect_repo_git_meta(repo_root: &Path) -> (Option<String>, Option<String>, Option<String>) {
    let dot_git = repo_root.join(".git");
    let Ok(meta) = fs::symlink_metadata(&dot_git) else {
        return (None, None, None);
    };
    if is_reparse_or_symlink(&meta) {
        return (None, None, None);
    }

    let (head, branch) = match run_git_capture(repo_root, &["rev-parse", "HEAD", "--abbrev-ref", "HEAD"]) {
        Some(out) => {
            let mut lines = out.lines();
            let h = lines
                .next()
                .map(|s| s.trim().to_ascii_lowercase())
                .filter(|s| !s.is_empty());
            let b = lines
                .next()
                .map(|s| s.trim().to_string())
                .filter(|s| !s.is_empty() && s != "HEAD");
            (h, b)
        }
        None => (None, None),
    };
    let remote = run_git_capture(repo_root, &["config", "--get", "remote.origin.url"])
        .map(|s| normalize_git_url(s.trim()))
        .filter(|s| !s.is_empty());

    (head, branch, remote)
}

fn run_git_capture(repo_root: &Path, args: &[&str]) -> Option<String> {
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
        let mut limited = stdout.take(MAX_GIT_META_BYTES.saturating_add(1));
        let _ = limited.read_to_end(&mut buf);
        buf
    });

    let deadline = Instant::now().checked_add(GIT_META_TIMEOUT);
    let status = loop {
        match child.try_wait() {
            Ok(Some(st)) => break Some(st),
            Ok(None) => {
                if deadline.is_some_and(|d| Instant::now() >= d) {
                    let _ = child.kill();
                    let _ = child.wait();
                    break None;
                }
                thread::sleep(Duration::from_millis(5));
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
    if (buf.len() as u64) > MAX_GIT_META_BYTES {
        buf.truncate(MAX_GIT_META_BYTES as usize);
    }
    Some(String::from_utf8_lossy(&buf).into_owned())
}

fn is_regular_non_symlink(path: &Path) -> bool {
    fs::symlink_metadata(path)
        .is_ok_and(|meta| !is_reparse_or_symlink(&meta) && meta.is_file())
}

fn rel_posix(root: &Path, path: &Path) -> String {
    path.strip_prefix(root)
        .unwrap_or(path)
        .to_string_lossy()
        .replace('\\', "/")
}

fn normalize_abs_path(path: &Path) -> PathBuf {
    let abs = if path.is_absolute() {
        path.to_path_buf()
    } else {
        std::env::current_dir()
            .map(|cwd| cwd.join(path))
            .unwrap_or_else(|_| path.to_path_buf())
    };
    lexical_normalize(&abs)
}

fn lexical_normalize(path: &Path) -> PathBuf {
    let mut out = PathBuf::new();
    for comp in path.components() {
        match comp {
            Component::CurDir => {}
            Component::ParentDir => {
                out.pop();
            }
            other => out.push(other.as_os_str()),
        }
    }
    out
}

fn path_match_key(path: &Path) -> String {
    let posix = lexical_normalize(path).to_string_lossy().replace('\\', "/");
    #[cfg(windows)]
    {
        posix.to_ascii_lowercase()
    }
    #[cfg(not(windows))]
    {
        posix
    }
}

fn path_key_contains(root_key: &str, candidate_key: &str) -> bool {
    if candidate_key == root_key {
        return true;
    }
    let trimmed = root_key.trim_end_matches('/');
    candidate_key
        .strip_prefix(trimmed)
        .is_some_and(|rest| rest.starts_with('/'))
}
