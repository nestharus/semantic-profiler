//! Portable data structures for semantic snapshots, relationship-topology
//! analysis, portable graph-edge exports, longitudinal deltas, and Layer 2 CRW
//! handoff packets.

use serde::{Deserialize, Serialize};

pub const SNAPSHOT_SCHEMA_VERSION: u32 = 1;
pub const DELTA_SCHEMA_VERSION: u32 = 1;
pub const CRW_PACKET_SCHEMA_VERSION: u32 = 1;
pub const GRAPH_EDGES_SCHEMA_VERSION: u32 = 1;
pub const CHECK_REPORT_SCHEMA_VERSION: u32 = 1;

/// Returns `true` for generic ephemeral stream or capture filenames that should
/// never be flagged as smeared persistent write ownership across modules.
pub fn is_ephemeral_write_target(target: &str) -> bool {
    let lower = target.trim().replace('\\', "/").to_ascii_lowercase();
    if matches!(
        lower.as_str(),
        "/dev/null" | "/dev/stdout" | "/dev/stderr" | "nul"
    ) {
        return true;
    }
    let base = lower.rsplit('/').next().unwrap_or(lower.as_str());
    matches!(
        base,
        "stdout"
            | "stderr"
            | "stdout.txt"
            | "stderr.txt"
            | "stdout.bin"
            | "stderr.bin"
            | "prompt.txt"
    )
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Language {
    Rust,
    Python,
    TypeScript,
    JavaScript,
    Go,
    Shell,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum FileRole {
    Production,
    Test,
    Eval,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum FileClassification {
    Standard,
    StaticDataTable,
    FlatDispatcher,
    TestOrEval,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct FunctionMetrics {
    pub name: String,
    pub start_line: usize,
    pub end_line: usize,
    pub loc: usize,
    pub param_count: usize,
    pub max_nesting_depth: usize,
    pub is_flat_dispatcher: bool,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct SuppressionMetrics {
    pub total: usize,
    pub blanket: usize,
    pub narrow: usize,
    pub justified_narrow: usize,
    pub directives: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ReachInSignal {
    pub kind: String,
    pub target: String,
    pub line: usize,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct WriteSinkHit {
    pub target: String,
    pub sink: String,
    pub line: usize,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct FileProfile {
    pub path: String,
    pub language: Language,
    pub role: FileRole,
    pub classification: FileClassification,
    pub sha256: String,
    pub total_loc: usize,
    pub prod_loc: usize,
    pub inline_test_loc: usize,
    pub est_tokens: usize,
    pub function_count: usize,
    pub max_fn_loc: usize,
    pub max_fn_name: Option<String>,
    pub max_nesting_depth: usize,
    pub max_param_count: usize,
    pub functions: Vec<FunctionMetrics>,
    pub suppressions: SuppressionMetrics,
    pub internal_imports: Vec<String>,
    #[serde(default)]
    pub import_paths: Vec<String>,
    #[serde(default)]
    pub mod_decl_paths: Vec<String>,
    #[serde(default)]
    pub reach_ins: Vec<ReachInSignal>,
    #[serde(default)]
    pub write_targets: Vec<WriteSinkHit>,
    #[serde(default)]
    pub layer: Option<String>,
    #[serde(default)]
    pub topology_role: String,
    pub fan_in: usize,
    pub fan_out: usize,
    #[serde(default)]
    pub nexus_score: usize,
    #[serde(default)]
    pub transitive_dependents: usize,
    #[serde(default)]
    pub transitive_dependent_tokens: usize,
    pub churn_commits: usize,
    pub co_change_partners: usize,
    pub dampening_factor: f64,
    pub dampening_reason: Option<String>,
    pub raw_hotspot_score: f64,
    pub hotspot_score: f64,
    pub parse_fallback: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CoChangePair {
    pub file_a: String,
    pub file_b: String,
    pub co_changes: usize,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SkippedFile {
    pub path: String,
    pub reason: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LayerSpec {
    pub name: String,
    pub globs: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LayerEdgeRule {
    pub from: String,
    pub to: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BypassFinding {
    pub kind: String,
    pub from: String,
    pub via: Option<String>,
    pub to: String,
    pub detail: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SccCluster {
    pub id: String,
    pub files: Vec<String>,
    pub total_prod_loc: usize,
    pub total_est_tokens: usize,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SmearedWriteTarget {
    pub target: String,
    pub writer_count: usize,
    pub writers: Vec<String>,
    pub sinks: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct NexusNode {
    pub path: String,
    pub fan_in: usize,
    pub fan_out: usize,
    pub nexus_score: usize,
    pub transitive_dependents: usize,
    pub transitive_dependent_tokens: usize,
    pub layer: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PhantomCoupling {
    pub file_a: String,
    pub file_b: String,
    pub co_changes: usize,
    pub combined_est_tokens: usize,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct TopologyReport {
    #[serde(default)]
    pub sccs: Vec<SccCluster>,
    #[serde(default)]
    pub bypasses: Vec<BypassFinding>,
    #[serde(default)]
    pub smeared_writes: Vec<SmearedWriteTarget>,
    #[serde(default)]
    pub top_nexus_nodes: Vec<NexusNode>,
    #[serde(default)]
    pub phantom_couplings: Vec<PhantomCoupling>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct GraphNode {
    pub id: String,
    pub language: Language,
    pub role: FileRole,
    pub layer: Option<String>,
    pub topology_role: String,
    pub prod_loc: usize,
    pub est_tokens: usize,
    pub fan_in: usize,
    pub fan_out: usize,
    pub nexus_score: usize,
    pub transitive_dependents: usize,
    pub transitive_dependent_tokens: usize,
    pub scc_id: Option<String>,
    pub hotspot_score: f64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct GraphEdge {
    pub kind: String,
    pub from: String,
    pub to: String,
    pub weight: usize,
    pub label: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct GraphEdgesExport {
    pub schema_version: u32,
    pub repo_label: String,
    pub commit: Option<String>,
    pub node_count: usize,
    pub edge_count: usize,
    pub nodes: Vec<GraphNode>,
    pub edges: Vec<GraphEdge>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct RepoSummary {
    pub total_files: usize,
    pub prod_files: usize,
    pub test_files: usize,
    pub eval_files: usize,
    pub total_loc: usize,
    pub prod_loc: usize,
    pub test_and_eval_loc: usize,
    pub est_prod_tokens: usize,
    pub median_prod_loc: usize,
    pub p95_prod_loc: usize,
    pub prod_files_over_1000_loc: usize,
    pub top_hotspot_score: f64,
    pub files_with_suppressions: usize,
    pub total_suppressions: usize,
    pub blanket_suppressions: usize,
    pub dampened_files: usize,
    #[serde(default)]
    pub scc_count: usize,
    #[serde(default)]
    pub bypass_count: usize,
    #[serde(default)]
    pub smeared_write_count: usize,
    #[serde(default)]
    pub phantom_coupling_count: usize,
}

#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SemanticBudgets {
    #[serde(default)]
    pub max_hotspot_score: Option<f64>,
    #[serde(default)]
    pub max_prod_fn_loc: Option<usize>,
    #[serde(default)]
    pub max_blanket_suppressions: Option<usize>,
    #[serde(default)]
    pub max_scc_count: Option<usize>,
    #[serde(default)]
    pub max_bypass_count: Option<usize>,
    #[serde(default)]
    pub max_smeared_write_count: Option<usize>,
    #[serde(default)]
    pub max_phantom_coupling_count: Option<usize>,
}

impl SemanticBudgets {
    pub fn has_any(&self) -> bool {
        self.max_hotspot_score.is_some()
            || self.max_prod_fn_loc.is_some()
            || self.max_blanket_suppressions.is_some()
            || self.max_scc_count.is_some()
            || self.max_bypass_count.is_some()
            || self.max_smeared_write_count.is_some()
            || self.max_phantom_coupling_count.is_some()
    }
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ProfileContext {
    pub loaded_from: Option<String>,
    pub domain_vocabulary: Vec<String>,
    pub cohesive_data_globs: Vec<String>,
    pub flat_dispatcher_globs: Vec<String>,
    #[serde(default)]
    pub layers: Vec<LayerSpec>,
    #[serde(default)]
    pub allowed_edges: Vec<LayerEdgeRule>,
    #[serde(default)]
    pub forbidden_bypasses: Vec<LayerEdgeRule>,
    pub budgets: Option<SemanticBudgets>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Snapshot {
    pub schema_version: u32,
    pub repo_label: String,
    pub commit: Option<String>,
    pub git_available: bool,
    pub git_window: usize,
    pub git_commits_scanned: usize,
    pub profile: ProfileContext,
    pub summary: RepoSummary,
    #[serde(default)]
    pub topology: TopologyReport,
    pub files: Vec<FileProfile>,
    pub co_change_pairs: Vec<CoChangePair>,
    pub skipped_files: Vec<SkippedFile>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct JsonlRecord {
    pub schema_version: u32,
    pub repo_label: String,
    pub commit: Option<String>,
    pub summary: RepoSummary,
    pub top_hotspots: Vec<HotspotEntry>,
    pub top_co_change_pairs: Vec<CoChangePair>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct HotspotEntry {
    pub path: String,
    pub language: Language,
    pub classification: FileClassification,
    pub prod_loc: usize,
    pub est_tokens: usize,
    pub max_fn_loc: usize,
    pub max_fn_name: Option<String>,
    pub max_nesting_depth: usize,
    pub max_param_count: usize,
    pub fan_in: usize,
    pub fan_out: usize,
    #[serde(default)]
    pub nexus_score: usize,
    #[serde(default)]
    pub transitive_dependents: usize,
    #[serde(default)]
    pub transitive_dependent_tokens: usize,
    pub churn_commits: usize,
    pub co_change_partners: usize,
    pub blanket_suppressions: usize,
    pub narrow_suppressions: usize,
    pub dampening_factor: f64,
    pub dampening_reason: Option<String>,
    pub hotspot_score: f64,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct FileDelta {
    pub path: String,
    pub status: String,
    pub prod_loc_delta: i64,
    pub est_tokens_delta: i64,
    pub max_fn_loc_delta: i64,
    pub max_nesting_delta: i64,
    pub blanket_suppressions_delta: i64,
    pub total_suppressions_delta: i64,
    pub hotspot_score_base: f64,
    pub hotspot_score_head: f64,
    pub hotspot_score_delta: f64,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct CoChangeDelta {
    pub file_a: String,
    pub file_b: String,
    pub base_co_changes: usize,
    pub head_co_changes: usize,
    pub delta: i64,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct BudgetViolation {
    pub rule: String,
    pub target: String,
    pub actual: f64,
    pub limit: f64,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct SnapshotDelta {
    pub schema_version: u32,
    pub repo_label: String,
    pub base_commit: Option<String>,
    pub head_commit: Option<String>,
    pub prod_loc_delta: i64,
    pub est_prod_tokens_delta: i64,
    pub top_hotspot_score_delta: f64,
    pub total_suppressions_delta: i64,
    pub blanket_suppressions_delta: i64,
    #[serde(default)]
    pub scc_count_delta: i64,
    #[serde(default)]
    pub bypass_count_delta: i64,
    #[serde(default)]
    pub smeared_write_count_delta: i64,
    #[serde(default)]
    pub phantom_coupling_count_delta: i64,
    pub rising_hotspots: Vec<FileDelta>,
    pub improved_files: Vec<FileDelta>,
    pub suppression_regressions: Vec<FileDelta>,
    pub co_change_deltas: Vec<CoChangeDelta>,
    pub budget_violations: Vec<BudgetViolation>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct CrwHandoffPacket {
    pub schema_version: u32,
    pub packet_kind: String,
    pub target_families: Vec<String>,
    pub repo_label: String,
    pub commit: Option<String>,
    pub summary: RepoSummary,
    pub profile: ProfileContext,
    pub top_hotspots: Vec<HotspotEntry>,
    pub dampened_counterexamples: Vec<HotspotEntry>,
    pub co_change_clusters: Vec<CoChangePair>,
    pub blanket_suppression_files: Vec<HotspotEntry>,
    #[serde(default)]
    pub topology: TopologyReport,
    pub drift: Option<SnapshotDelta>,
    pub challenge_notes: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct CheckReport {
    pub schema_version: u32,
    pub passed: bool,
    pub repo_label: String,
    pub commit: Option<String>,
    pub profile_loaded_from: Option<String>,
    pub budgets_configured: bool,
    pub warnings: Vec<String>,
    pub summary: RepoSummary,
    pub budget_violations: Vec<BudgetViolation>,
    pub top_hotspots: Vec<HotspotEntry>,
    pub topology: TopologyReport,
    pub delta: Option<SnapshotDelta>,
}
