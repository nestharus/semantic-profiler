//! Portable data structures for the Tier 2 Cross-Repo Ecosystem Graph.
//! Pure zero-fan-out leaf module with deterministic serialization schemas.

use serde::{Deserialize, Serialize};
use std::path::PathBuf;

pub const ECOSYSTEM_GRAPH_FORMAT: &str = "semantic-ecosystem-graph/1";
pub const ECOSYSTEM_GRAPH_SCHEMA_VERSION: u32 = 1;

#[derive(Debug, Clone, Default)]
pub struct EcosystemScanOptions {
    pub workspace_root: Option<PathBuf>,
    pub roots: Vec<PathBuf>,
    pub scan_repos: bool,
    pub impact_target: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct EcosystemGraph {
    pub format: String,
    pub schema_version: u32,
    pub discovery_mode: String,
    pub summary: EcosystemSummary,
    pub nodes: Vec<EcosystemRepoNode>,
    pub edges: Vec<EcosystemEdge>,
    pub sccs: Vec<EcosystemScc>,
    pub pin_skew: Vec<PinSkewEntry>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub impact: Option<ImpactReport>,
    pub skipped: Vec<EcosystemSkipped>,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct EcosystemSummary {
    pub repo_count: usize,
    pub edge_count: usize,
    pub scc_count: usize,
    pub pin_skew_count: usize,
    pub rust_repo_count: usize,
    pub python_repo_count: usize,
    pub domain_repo_count: usize,
    pub repos_with_profile: usize,
    pub repos_with_baseline: usize,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct EcosystemRepoNode {
    pub id: String,
    pub name: String,
    pub relative_path: String,
    pub git_head: Option<String>,
    pub git_branch: Option<String>,
    pub git_remote: Option<String>,
    pub ecosystems: Vec<String>,
    pub packages: Vec<PublishedPackage>,
    pub has_semantic_profile: bool,
    pub has_semantic_baseline: bool,
    pub semantic_health: Option<SemanticHealthRollup>,
    pub fan_in: usize,
    pub fan_out: usize,
    pub scc_id: Option<String>,
    pub transitive_dependents: Vec<String>,
    pub transitive_dependent_count: usize,
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub struct PublishedPackage {
    pub ecosystem: String,
    pub name: String,
    pub version: Option<String>,
    pub manifest_path: String,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct SemanticHealthRollup {
    pub source: String,
    pub commit: Option<String>,
    pub prod_loc: usize,
    pub scc_count: usize,
    pub top_hotspot_score: f64,
    pub top_hotspot_path: Option<String>,
    pub bypass_count: usize,
    pub smeared_write_count: usize,
    pub blanket_suppressions: usize,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EcosystemEdge {
    pub from: String,
    pub to: String,
    pub ecosystem: String,
    pub kind: String,
    pub dependency_section: Option<String>,
    pub package_name: String,
    pub manifest_path: String,
    pub declared_spec: Option<String>,
    pub pinned_rev: Option<String>,
    pub pinned_branch: Option<String>,
    pub pinned_tag: Option<String>,
    pub locked_rev: Option<String>,
    pub target_head: Option<String>,
    pub pin_skew: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PinSkewEntry {
    pub from_repo: String,
    pub to_repo: String,
    pub package_name: String,
    pub manifest_path: String,
    pub lockfile_path: Option<String>,
    pub declared_rev: Option<String>,
    pub declared_branch: Option<String>,
    pub declared_tag: Option<String>,
    pub resolved_sha: String,
    pub target_head_sha: String,
    pub skew_source: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EcosystemScc {
    pub id: String,
    pub repos: Vec<String>,
    pub edge_count: usize,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ImpactPath {
    pub repo: String,
    pub path: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ImpactReport {
    pub target_repo: String,
    pub direct_dependents: Vec<String>,
    pub transitive_dependents: Vec<String>,
    pub transitive_dependent_count: usize,
    pub direct_dependencies: Vec<String>,
    pub impact_paths: Vec<ImpactPath>,
    pub scc_members: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EcosystemSkipped {
    pub path: String,
    pub reason: String,
}
