//! Longitudinal snapshot comparison (`delta --base <a.json> --head <b.json>`).

use crate::model::{
    BudgetViolation, CoChangeDelta, DELTA_SCHEMA_VERSION, FileDelta, FileProfile, FileRole,
    SemanticBudgets, Snapshot, SnapshotDelta,
};
use crate::scoring::round2;
use std::collections::{BTreeMap, BTreeSet};

fn sat_to_i64(v: usize) -> i64 {
    i64::try_from(v).unwrap_or(i64::MAX)
}

fn sat_diff(head: usize, base: usize) -> i64 {
    sat_to_i64(head).saturating_sub(sat_to_i64(base))
}

pub fn compute_delta(base: &Snapshot, head: &Snapshot) -> SnapshotDelta {
    let base_map: BTreeMap<&str, &FileProfile> = base
        .files
        .iter()
        .filter(|f| f.role == FileRole::Production)
        .map(|f| (f.path.as_str(), f))
        .collect();
    let head_map: BTreeMap<&str, &FileProfile> = head
        .files
        .iter()
        .filter(|f| f.role == FileRole::Production)
        .map(|f| (f.path.as_str(), f))
        .collect();

    let mut all_paths: BTreeSet<&str> = BTreeSet::new();
    all_paths.extend(base_map.keys().copied());
    all_paths.extend(head_map.keys().copied());

    let mut rising = Vec::new();
    let mut improved = Vec::new();
    let mut suppression_regressions = Vec::new();

    for path in all_paths {
        let fd = match (base_map.get(path), head_map.get(path)) {
            (None, Some(h)) => FileDelta {
                path: path.to_string(),
                status: "added".to_string(),
                prod_loc_delta: sat_to_i64(h.prod_loc),
                est_tokens_delta: sat_to_i64(h.est_tokens),
                max_fn_loc_delta: sat_to_i64(h.max_fn_loc),
                max_nesting_delta: sat_to_i64(h.max_nesting_depth),
                blanket_suppressions_delta: sat_to_i64(h.suppressions.blanket),
                total_suppressions_delta: sat_to_i64(h.suppressions.total),
                hotspot_score_base: 0.0,
                hotspot_score_head: h.hotspot_score,
                hotspot_score_delta: round2(h.hotspot_score),
            },
            (Some(b), None) => FileDelta {
                path: path.to_string(),
                status: "removed".to_string(),
                prod_loc_delta: -sat_to_i64(b.prod_loc),
                est_tokens_delta: -sat_to_i64(b.est_tokens),
                max_fn_loc_delta: -sat_to_i64(b.max_fn_loc),
                max_nesting_delta: -sat_to_i64(b.max_nesting_depth),
                blanket_suppressions_delta: -sat_to_i64(b.suppressions.blanket),
                total_suppressions_delta: -sat_to_i64(b.suppressions.total),
                hotspot_score_base: b.hotspot_score,
                hotspot_score_head: 0.0,
                hotspot_score_delta: round2(-b.hotspot_score),
            },
            (Some(b), Some(h)) => FileDelta {
                path: path.to_string(),
                status: "modified".to_string(),
                prod_loc_delta: sat_diff(h.prod_loc, b.prod_loc),
                est_tokens_delta: sat_diff(h.est_tokens, b.est_tokens),
                max_fn_loc_delta: sat_diff(h.max_fn_loc, b.max_fn_loc),
                max_nesting_delta: sat_diff(h.max_nesting_depth, b.max_nesting_depth),
                blanket_suppressions_delta: sat_diff(
                    h.suppressions.blanket,
                    b.suppressions.blanket,
                ),
                total_suppressions_delta: sat_diff(h.suppressions.total, b.suppressions.total),
                hotspot_score_base: b.hotspot_score,
                hotspot_score_head: h.hotspot_score,
                hotspot_score_delta: round2(h.hotspot_score - b.hotspot_score),
            },
            (None, None) => continue,
        };

        if fd.blanket_suppressions_delta > 0 || fd.total_suppressions_delta > 0 {
            suppression_regressions.push(fd.clone());
        }
        if fd.hotspot_score_delta > 0.01 {
            rising.push(fd);
        } else if fd.hotspot_score_delta < -0.01 {
            improved.push(fd);
        }
    }

    rising.sort_by(|a, b| {
        b.hotspot_score_delta
            .total_cmp(&a.hotspot_score_delta)
            .then_with(|| a.path.cmp(&b.path))
    });
    improved.sort_by(|a, b| {
        a.hotspot_score_delta
            .total_cmp(&b.hotspot_score_delta)
            .then_with(|| a.path.cmp(&b.path))
    });
    suppression_regressions.sort_by(|a, b| {
        b.blanket_suppressions_delta
            .cmp(&a.blanket_suppressions_delta)
            .then_with(|| b.total_suppressions_delta.cmp(&a.total_suppressions_delta))
            .then_with(|| a.path.cmp(&b.path))
    });

    let co_change_deltas = compute_co_change_deltas(base, head);
    let budget_violations = evaluate_budgets(head, head.profile.budgets.as_ref());

    SnapshotDelta {
        schema_version: DELTA_SCHEMA_VERSION,
        repo_label: head.repo_label.clone(),
        base_commit: base.commit.clone(),
        head_commit: head.commit.clone(),
        prod_loc_delta: sat_diff(head.summary.prod_loc, base.summary.prod_loc),
        est_prod_tokens_delta: sat_diff(head.summary.est_prod_tokens, base.summary.est_prod_tokens),
        top_hotspot_score_delta: round2(
            head.summary.top_hotspot_score - base.summary.top_hotspot_score,
        ),
        total_suppressions_delta: sat_diff(
            head.summary.total_suppressions,
            base.summary.total_suppressions,
        ),
        blanket_suppressions_delta: sat_diff(
            head.summary.blanket_suppressions,
            base.summary.blanket_suppressions,
        ),
        scc_count_delta: sat_diff(head.summary.scc_count, base.summary.scc_count),
        bypass_count_delta: sat_diff(head.summary.bypass_count, base.summary.bypass_count),
        smeared_write_count_delta: sat_diff(
            head.summary.smeared_write_count,
            base.summary.smeared_write_count,
        ),
        phantom_coupling_count_delta: sat_diff(
            head.summary.phantom_coupling_count,
            base.summary.phantom_coupling_count,
        ),
        rising_hotspots: rising,
        improved_files: improved,
        suppression_regressions,
        co_change_deltas,
        budget_violations,
    }
}

fn compute_co_change_deltas(base: &Snapshot, head: &Snapshot) -> Vec<CoChangeDelta> {
    let mut base_pairs: BTreeMap<(&str, &str), usize> = BTreeMap::new();
    for p in &base.co_change_pairs {
        base_pairs.insert((p.file_a.as_str(), p.file_b.as_str()), p.co_changes);
    }
    let mut head_pairs: BTreeMap<(&str, &str), usize> = BTreeMap::new();
    for p in &head.co_change_pairs {
        head_pairs.insert((p.file_a.as_str(), p.file_b.as_str()), p.co_changes);
    }

    let mut all_keys: BTreeSet<(&str, &str)> = BTreeSet::new();
    all_keys.extend(base_pairs.keys().copied());
    all_keys.extend(head_pairs.keys().copied());

    let mut deltas = Vec::new();
    for (a, b) in all_keys {
        let bv = base_pairs.get(&(a, b)).copied().unwrap_or(0);
        let hv = head_pairs.get(&(a, b)).copied().unwrap_or(0);
        let diff = sat_diff(hv, bv);
        if diff != 0 {
            deltas.push(CoChangeDelta {
                file_a: a.to_string(),
                file_b: b.to_string(),
                base_co_changes: bv,
                head_co_changes: hv,
                delta: diff,
            });
        }
    }
    deltas.sort_by(|x, y| {
        y.delta
            .cmp(&x.delta)
            .then_with(|| x.file_a.cmp(&y.file_a))
            .then_with(|| x.file_b.cmp(&y.file_b))
    });
    deltas
}

pub fn evaluate_budgets(
    head: &Snapshot,
    budgets: Option<&SemanticBudgets>,
) -> Vec<BudgetViolation> {
    let Some(b) = budgets else {
        return Vec::new();
    };
    let mut violations = Vec::new();

    if let Some(max_score) = b.max_hotspot_score {
        if !max_score.is_finite() || max_score < 0.0 {
            violations.push(BudgetViolation {
                rule: "max_hotspot_score".to_string(),
                target: "<budget-config>".to_string(),
                actual: 0.0,
                limit: if max_score.is_finite() { max_score } else { 0.0 },
            });
        } else {
            for f in &head.files {
                if f.role == FileRole::Production
                    && (!f.hotspot_score.is_finite() || f.hotspot_score > max_score)
                {
                    violations.push(BudgetViolation {
                        rule: "max_hotspot_score".to_string(),
                        target: f.path.clone(),
                        actual: if f.hotspot_score.is_finite() {
                            f.hotspot_score
                        } else {
                            f64::MAX
                        },
                        limit: max_score,
                    });
                }
            }
        }
    }
    if let Some(max_fn_loc) = b.max_prod_fn_loc {
        for f in &head.files {
            if f.role == FileRole::Production
                && f.dampening_factor >= 1.0
                && f.max_fn_loc > max_fn_loc
            {
                violations.push(BudgetViolation {
                    rule: "max_prod_fn_loc".to_string(),
                    target: f.path.clone(),
                    actual: f.max_fn_loc as f64,
                    limit: max_fn_loc as f64,
                });
            }
        }
    }
    if let Some(max_blanket) = b.max_blanket_suppressions
        && head.summary.blanket_suppressions > max_blanket
    {
        violations.push(BudgetViolation {
            rule: "max_blanket_suppressions".to_string(),
            target: "<repo>".to_string(),
            actual: head.summary.blanket_suppressions as f64,
            limit: max_blanket as f64,
        });
    }
    if let Some(max_sccs) = b.max_scc_count
        && head.summary.scc_count > max_sccs
    {
        violations.push(BudgetViolation {
            rule: "max_scc_count".to_string(),
            target: "<repo>".to_string(),
            actual: head.summary.scc_count as f64,
            limit: max_sccs as f64,
        });
    }
    if let Some(max_bypasses) = b.max_bypass_count
        && head.summary.bypass_count > max_bypasses
    {
        violations.push(BudgetViolation {
            rule: "max_bypass_count".to_string(),
            target: "<repo>".to_string(),
            actual: head.summary.bypass_count as f64,
            limit: max_bypasses as f64,
        });
    }
    if let Some(max_smeared) = b.max_smeared_write_count
        && head.summary.smeared_write_count > max_smeared
    {
        violations.push(BudgetViolation {
            rule: "max_smeared_write_count".to_string(),
            target: "<repo>".to_string(),
            actual: head.summary.smeared_write_count as f64,
            limit: max_smeared as f64,
        });
    }
    if let Some(max_phantom) = b.max_phantom_coupling_count
        && head.summary.phantom_coupling_count > max_phantom
    {
        violations.push(BudgetViolation {
            rule: "max_phantom_coupling_count".to_string(),
            target: "<repo>".to_string(),
            actual: head.summary.phantom_coupling_count as f64,
            limit: max_phantom as f64,
        });
    }
    violations
}
