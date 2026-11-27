//! Composite hotspot scoring, internal fan-in/fan-out resolution, and
//! explicit false-positive dampening for static tables and flat dispatchers.

use crate::graph_topology::ProductionGraph;
use crate::model::{
    FileClassification, FileProfile, FileRole, HotspotEntry, RepoSummary, TopologyReport,
};
use crate::profile_config::RepoProfile;

pub fn resolve_fan_in_out_and_score(
    files: &mut [FileProfile],
    graph: &ProductionGraph,
    profile: &RepoProfile,
) {
    for (idx, file) in files.iter_mut().enumerate() {
        file.fan_in = graph.rev_adj[idx].len();
        file.fan_out = graph.adj[idx].len();
        score_file(file, profile);
    }
}

fn score_file(file: &mut FileProfile, profile: &RepoProfile) {
    if file.role != FileRole::Production {
        file.classification = FileClassification::TestOrEval;
        file.dampening_factor = 0.0;
        file.dampening_reason = Some("test/eval file scored separately from production".to_string());
        file.raw_hotspot_score = 0.0;
        file.hotspot_score = 0.0;
        return;
    }

    let size_component = (file.prod_loc as f64 / 50.0) + (file.est_tokens as f64 / 600.0);
    let nesting_excess = file.max_nesting_depth.saturating_sub(3) as f64;
    let param_excess = file.max_param_count.saturating_sub(5) as f64;
    let complexity_component = (file.max_fn_loc as f64 / 15.0)
        + (nesting_excess * nesting_excess * 3.0)
        + (param_excess * 4.0);

    let coupling_multiplier = 1.0
        + (file.churn_commits as f64 * 0.25)
        + (file.co_change_partners as f64 * 0.15)
        + ((file.fan_in + file.fan_out) as f64 * 0.10);

    let unjustified_narrow = file
        .suppressions
        .narrow
        .saturating_sub(file.suppressions.justified_narrow);
    let suppression_penalty =
        (file.suppressions.blanket as f64 * 25.0) + (unjustified_narrow as f64 * 5.0);

    let base_raw = (size_component + complexity_component) * coupling_multiplier;
    let raw = base_raw + suppression_penalty;

    let (classification, factor, reason) =
        if profile.is_cohesive_data(&file.path) && file.suppressions.blanket == 0 {
            (
                FileClassification::StaticDataTable,
                0.05,
                Some("calibrated cohesive static data table (profile glob)".to_string()),
            )
        } else if file.classification == FileClassification::StaticDataTable
            && file.suppressions.blanket == 0
        {
            (
                FileClassification::StaticDataTable,
                0.05,
                Some("static data/lookup table with zero production functions".to_string()),
            )
        } else if profile.is_flat_dispatcher(&file.path)
            && file.max_nesting_depth <= 3
            && file.suppressions.blanket == 0
        {
            (
                FileClassification::FlatDispatcher,
                0.20,
                Some("calibrated flat exhaustive dispatcher (profile glob)".to_string()),
            )
        } else if file.classification == FileClassification::FlatDispatcher
            && file.suppressions.blanket == 0
        {
            (
                FileClassification::FlatDispatcher,
                0.20,
                Some("flat exhaustive match dispatcher delegating with shallow arms".to_string()),
            )
        } else {
            (FileClassification::Standard, 1.0, None)
        };

    file.classification = classification;
    file.dampening_factor = factor;
    file.dampening_reason = reason;
    file.raw_hotspot_score = round2(raw);
    // Apply suppression_penalty AFTER dampening so blanket suppressions cannot hide under a dampened glob.
    file.hotspot_score = round2(base_raw * factor + suppression_penalty);
}

pub fn summarize_repo(files: &[FileProfile], topology: &TopologyReport) -> RepoSummary {
    let mut prod_locs: Vec<usize> = Vec::new();
    let mut prod_files = 0usize;
    let mut test_files = 0usize;
    let mut eval_files = 0usize;
    let mut total_loc = 0usize;
    let mut prod_loc = 0usize;
    let mut test_and_eval_loc = 0usize;
    let mut est_prod_tokens = 0usize;
    let mut prod_files_over_1000_loc = 0usize;
    let mut top_hotspot_score = 0.0f64;
    let mut files_with_suppressions = 0usize;
    let mut total_suppressions = 0usize;
    let mut blanket_suppressions = 0usize;
    let mut dampened_files = 0usize;

    for f in files {
        total_loc += f.total_loc;
        match f.role {
            FileRole::Production => {
                prod_files += 1;
                prod_loc += f.prod_loc;
                test_and_eval_loc += f.inline_test_loc;
                est_prod_tokens += f.est_tokens;
                prod_locs.push(f.prod_loc);
                if f.prod_loc > 1000 {
                    prod_files_over_1000_loc += 1;
                }
                if f.hotspot_score > top_hotspot_score {
                    top_hotspot_score = f.hotspot_score;
                }
                if f.suppressions.total > 0 {
                    files_with_suppressions += 1;
                    total_suppressions += f.suppressions.total;
                    blanket_suppressions += f.suppressions.blanket;
                }
                if f.dampening_factor < 1.0 {
                    dampened_files += 1;
                }
            }
            FileRole::Test => {
                test_files += 1;
                test_and_eval_loc += f.total_loc;
            }
            FileRole::Eval => {
                eval_files += 1;
                test_and_eval_loc += f.total_loc;
            }
        }
    }

    prod_locs.sort_unstable();
    let median_prod_loc = percentile(&prod_locs, 50);
    let p95_prod_loc = percentile(&prod_locs, 95);

    RepoSummary {
        total_files: files.len(),
        prod_files,
        test_files,
        eval_files,
        total_loc,
        prod_loc,
        test_and_eval_loc,
        est_prod_tokens,
        median_prod_loc,
        p95_prod_loc,
        prod_files_over_1000_loc,
        top_hotspot_score: round2(top_hotspot_score),
        files_with_suppressions,
        total_suppressions,
        blanket_suppressions,
        dampened_files,
        scc_count: topology.sccs.len(),
        bypass_count: topology.bypasses.len(),
        smeared_write_count: topology.smeared_writes.len(),
        phantom_coupling_count: topology.phantom_couplings.len(),
    }
}

pub fn top_hotspots(files: &[FileProfile], top_k: usize) -> Vec<HotspotEntry> {
    let mut prod: Vec<&FileProfile> = files
        .iter()
        .filter(|f| f.role == FileRole::Production)
        .collect();
    prod.sort_by(|a, b| {
        b.hotspot_score
            .total_cmp(&a.hotspot_score)
            .then_with(|| b.prod_loc.cmp(&a.prod_loc))
            .then_with(|| a.path.cmp(&b.path))
    });
    prod.into_iter().take(top_k).map(to_hotspot_entry).collect()
}

pub fn to_hotspot_entry(f: &FileProfile) -> HotspotEntry {
    HotspotEntry {
        path: f.path.clone(),
        language: f.language,
        classification: f.classification,
        prod_loc: f.prod_loc,
        est_tokens: f.est_tokens,
        max_fn_loc: f.max_fn_loc,
        max_fn_name: f.max_fn_name.clone(),
        max_nesting_depth: f.max_nesting_depth,
        max_param_count: f.max_param_count,
        fan_in: f.fan_in,
        fan_out: f.fan_out,
        nexus_score: f.nexus_score,
        transitive_dependents: f.transitive_dependents,
        transitive_dependent_tokens: f.transitive_dependent_tokens,
        churn_commits: f.churn_commits,
        co_change_partners: f.co_change_partners,
        blanket_suppressions: f.suppressions.blanket,
        narrow_suppressions: f.suppressions.narrow,
        dampening_factor: f.dampening_factor,
        dampening_reason: f.dampening_reason.clone(),
        hotspot_score: f.hotspot_score,
    }
}

fn percentile(sorted: &[usize], pct: usize) -> usize {
    if sorted.is_empty() {
        return 0;
    }
    let idx = ((sorted.len() - 1) * pct) / 100;
    sorted[idx]
}

pub fn round2(v: f64) -> f64 {
    if !v.is_finite() {
        return 0.0;
    }
    let scaled = v * 100.0;
    if !scaled.is_finite() {
        return v;
    }
    scaled.round() / 100.0
}
