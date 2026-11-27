//! Layer 1 deterministic static AST/git semantic profiler, relationship-topology
//! analyzer, portable graph-edge exporter, and Layer 2 CRW handoff packet builder.

pub mod cli;
pub mod crw_packet;
pub mod delta;
pub mod discovery;
pub mod ecosystem;
pub mod git_history;
pub mod graph_topology;
pub mod model;
pub mod profile_config;
pub mod rust_ast;
pub mod safe_io;
pub mod scoring;
pub mod text_analyzer;

use crate::discovery::{MAX_SOURCE_BYTES, discover_files};
use crate::git_history::collect_git_history;
use crate::graph_topology::{analyze_topology, build_import_graph};
use crate::model::{
    FileProfile, FileRole, Language, SNAPSHOT_SCHEMA_VERSION, SkippedFile, Snapshot,
};
use crate::profile_config::RepoProfile;
use crate::rust_ast::analyze_rust_source;
use crate::safe_io::read_file_bounded;
use crate::scoring::{resolve_fan_in_out_and_score, summarize_repo};
use crate::text_analyzer::analyze_text_source;
use sha2::{Digest, Sha256};
use std::collections::BTreeSet;
use std::fs;
use std::path::{Path, PathBuf};

#[derive(Debug, Clone)]
pub struct ScanOptions {
    pub git_window: usize,
    pub profile_path: Option<PathBuf>,
    pub include_evals: bool,
}

impl Default for ScanOptions {
    fn default() -> Self {
        Self {
            git_window: 100,
            profile_path: None,
            include_evals: false,
        }
    }
}

pub fn scan_repository(repo_root: &Path, options: &ScanOptions) -> Result<Snapshot, String> {
    let profile = RepoProfile::load(repo_root, options.profile_path.as_deref())?;
    let mut discovered = discover_files(repo_root, &profile, options.include_evals)?;

    let known_files: BTreeSet<String> = discovered
        .files
        .iter()
        .map(|f| f.rel_path.clone())
        .collect();
    let git = collect_git_history(repo_root, options.git_window, &known_files);

    let mut profiles: Vec<FileProfile> = Vec::with_capacity(discovered.files.len());
    for df in &discovered.files {
        let bytes = match read_file_bounded(&df.abs_path, MAX_SOURCE_BYTES) {
            Ok(b) => b,
            Err(e) => {
                discovered.skipped.push(SkippedFile {
                    path: df.rel_path.clone(),
                    reason: e,
                });
                continue;
            }
        };
        let Ok(raw_source) = String::from_utf8(bytes) else {
            discovered.skipped.push(SkippedFile {
                path: df.rel_path.clone(),
                reason: "non-UTF-8 file skipped".to_string(),
            });
            continue;
        };

        let sha256 = sha256_hex(raw_source.as_bytes());
        let source = raw_source.strip_prefix('\u{feff}').unwrap_or(&raw_source);
        let is_test_or_eval = df.role != FileRole::Production;
        let analyzed = match df.language {
            Language::Rust => analyze_rust_source(source, is_test_or_eval).unwrap_or_else(|| {
                analyze_text_source(source, Language::Rust, is_test_or_eval, true)
            }),
            other => analyze_text_source(source, other, is_test_or_eval, false),
        };

        let mut max_fn_loc = 0usize;
        let mut max_fn_name: Option<String> = None;
        let mut max_nesting_depth = 0usize;
        let mut max_param_count = 0usize;

        for f in &analyzed.functions {
            if f.loc > max_fn_loc {
                max_fn_loc = f.loc;
                max_fn_name = Some(f.name.clone());
            }
            if f.max_nesting_depth > max_nesting_depth {
                max_nesting_depth = f.max_nesting_depth;
            }
            if f.param_count > max_param_count {
                max_param_count = f.param_count;
            }
        }

        let churn_commits = git.churn_by_file.get(&df.rel_path).copied().unwrap_or(0);
        let co_change_partners = git.partners_by_file.get(&df.rel_path).copied().unwrap_or(0);

        profiles.push(FileProfile {
            path: df.rel_path.clone(),
            language: df.language,
            role: df.role,
            classification: analyzed.detected_classification,
            sha256,
            total_loc: analyzed.total_loc,
            prod_loc: analyzed.prod_loc,
            inline_test_loc: analyzed.inline_test_loc,
            est_tokens: analyzed.est_tokens,
            function_count: analyzed.functions.len(),
            max_fn_loc,
            max_fn_name,
            max_nesting_depth,
            max_param_count,
            functions: analyzed.functions,
            suppressions: analyzed.suppressions,
            internal_imports: analyzed.internal_imports,
            import_paths: analyzed.import_paths,
            mod_decl_paths: analyzed.mod_decl_paths,
            reach_ins: analyzed.reach_ins,
            write_targets: analyzed.write_targets,
            layer: None,
            topology_role: String::new(),
            fan_in: 0,
            fan_out: 0,
            nexus_score: 0,
            transitive_dependents: 0,
            transitive_dependent_tokens: 0,
            churn_commits,
            co_change_partners,
            dampening_factor: 1.0,
            dampening_reason: None,
            raw_hotspot_score: 0.0,
            hotspot_score: 0.0,
            parse_fallback: analyzed.parse_fallback,
        });
    }

    let graph = build_import_graph(&profiles);
    resolve_fan_in_out_and_score(&mut profiles, &graph, &profile);
    let topology = analyze_topology(&mut profiles, &graph, &git.co_change_pairs, &profile);
    let summary = summarize_repo(&profiles, &topology);

    let repo_label = repo_root
        .file_name()
        .and_then(|s| s.to_str())
        .map(String::from)
        .or_else(|| {
            fs::canonicalize(repo_root)
                .ok()
                .and_then(|p| p.file_name().and_then(|s| s.to_str()).map(String::from))
        })
        .unwrap_or_else(|| "repository".to_string());

    Ok(Snapshot {
        schema_version: SNAPSHOT_SCHEMA_VERSION,
        repo_label,
        commit: git.head_commit,
        git_available: git.available,
        git_window: options.git_window,
        git_commits_scanned: git.commits_scanned,
        profile: profile.to_context(),
        summary,
        topology,
        files: profiles,
        co_change_pairs: git.co_change_pairs,
        skipped_files: discovered.skipped,
    })
}

fn sha256_hex(bytes: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(bytes);
    let digest = hasher.finalize();
    let mut out = String::with_capacity(64);
    for byte in digest {
        use std::fmt::Write as _;
        let _ = write!(&mut out, "{byte:02x}");
    }
    out
}
