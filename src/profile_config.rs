//! Per-repository `semantic-profile.json` loading, validation, stratum
//! classification, and polynomial-time glob matching.

use crate::model::{LayerEdgeRule, LayerSpec, ProfileContext, SemanticBudgets};
use crate::safe_io::{is_reparse_or_symlink, read_file_bounded};
use serde::Deserialize;
use std::collections::BTreeSet;
use std::path::Path;

pub const MAX_PROFILE_BYTES: u64 = 256 * 1024;

#[derive(Debug, Clone, Default, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RawSemanticProfile {
    #[serde(default)]
    pub schema_version: Option<u32>,
    #[serde(default)]
    pub domain_vocabulary: Vec<String>,
    #[serde(default)]
    pub cohesive_data_globs: Vec<String>,
    #[serde(default)]
    pub flat_dispatcher_globs: Vec<String>,
    #[serde(default)]
    pub test_globs: Vec<String>,
    #[serde(default)]
    pub ignore_globs: Vec<String>,
    #[serde(default, alias = "strata")]
    pub layers: Vec<LayerSpec>,
    #[serde(default)]
    pub allowed_edges: Vec<LayerEdgeRule>,
    #[serde(default)]
    pub forbidden_bypasses: Vec<LayerEdgeRule>,
    #[serde(default)]
    pub budgets: Option<SemanticBudgets>,
}

#[derive(Debug, Clone, Default)]
pub struct RepoProfile {
    pub loaded_from: Option<String>,
    pub domain_vocabulary: Vec<String>,
    pub cohesive_data_globs: Vec<String>,
    pub flat_dispatcher_globs: Vec<String>,
    pub test_globs: Vec<String>,
    pub ignore_globs: Vec<String>,
    pub layers: Vec<LayerSpec>,
    pub allowed_edges: Vec<LayerEdgeRule>,
    pub forbidden_bypasses: Vec<LayerEdgeRule>,
    pub budgets: Option<SemanticBudgets>,
}

impl RepoProfile {
    pub fn load(repo_root: &Path, explicit_path: Option<&Path>) -> Result<Self, String> {
        let candidate = match explicit_path {
            Some(p) => Some((p.to_path_buf(), true)),
            None => {
                let default_path = repo_root.join("semantic-profile.json");
                if std::fs::symlink_metadata(&default_path).is_ok() {
                    Some((default_path, false))
                } else {
                    None
                }
            }
        };

        let Some((path, _required)) = candidate else {
            return Ok(Self::default());
        };

        let sym_meta = std::fs::symlink_metadata(&path)
            .map_err(|e| format!("missing semantic profile {}: {e}", path.display()))?;
        if is_reparse_or_symlink(&sym_meta) {
            return Err(format!(
                "refusing symlink or reparse point semantic profile: {}",
                path.display()
            ));
        }
        if !sym_meta.is_file() {
            return Err(format!(
                "semantic profile is not a regular file: {}",
                path.display()
            ));
        }

        let bytes = read_file_bounded(&path, MAX_PROFILE_BYTES)
            .map_err(|e| format!("failed to read semantic profile: {e}"))?;
        let raw_text = String::from_utf8(bytes)
            .map_err(|e| format!("semantic profile is not valid UTF-8: {e}"))?;
        let clean_text = raw_text.strip_prefix('\u{feff}').unwrap_or(&raw_text);
        let mut raw: RawSemanticProfile = serde_json::from_str(clean_text)
            .map_err(|e| format!("invalid semantic-profile.json: {e}"))?;

        if let Some(ver) = raw.schema_version
            && ver != 1
        {
            return Err(format!("unsupported semantic-profile schema_version: {ver}"));
        }

        if let Some(budgets) = &raw.budgets
            && let Some(max_score) = budgets.max_hotspot_score
            && (!max_score.is_finite() || max_score < 0.0)
        {
            return Err(format!(
                "invalid budgets.max_hotspot_score ({max_score}): must be finite and non-negative"
            ));
        }

        for layer in &mut raw.layers {
            layer.name = layer.name.trim().to_string();
        }
        for rule in &mut raw.allowed_edges {
            rule.from = rule.from.trim().to_string();
            rule.to = rule.to.trim().to_string();
        }
        for rule in &mut raw.forbidden_bypasses {
            rule.from = rule.from.trim().to_string();
            rule.to = rule.to.trim().to_string();
        }

        validate_layer_rules(&raw.layers, &raw.allowed_edges, &raw.forbidden_bypasses)?;

        let label = path
            .file_name()
            .and_then(|s| s.to_str())
            .unwrap_or("semantic-profile.json")
            .to_string();

        Ok(Self {
            loaded_from: Some(label),
            domain_vocabulary: raw.domain_vocabulary,
            cohesive_data_globs: raw.cohesive_data_globs,
            flat_dispatcher_globs: raw.flat_dispatcher_globs,
            test_globs: raw.test_globs,
            ignore_globs: raw.ignore_globs,
            layers: raw.layers,
            allowed_edges: raw.allowed_edges,
            forbidden_bypasses: raw.forbidden_bypasses,
            budgets: raw.budgets,
        })
    }

    pub fn to_context(&self) -> ProfileContext {
        ProfileContext {
            loaded_from: self.loaded_from.clone(),
            domain_vocabulary: self.domain_vocabulary.clone(),
            cohesive_data_globs: self.cohesive_data_globs.clone(),
            flat_dispatcher_globs: self.flat_dispatcher_globs.clone(),
            layers: self.layers.clone(),
            allowed_edges: self.allowed_edges.clone(),
            forbidden_bypasses: self.forbidden_bypasses.clone(),
            budgets: self.budgets.clone(),
        }
    }

    pub fn is_ignored(&self, rel_path: &str) -> bool {
        self.ignore_globs.iter().any(|g| glob_match(g, rel_path))
    }

    pub fn is_profile_test(&self, rel_path: &str) -> bool {
        self.test_globs.iter().any(|g| glob_match(g, rel_path))
    }

    pub fn is_cohesive_data(&self, rel_path: &str) -> bool {
        self.cohesive_data_globs
            .iter()
            .any(|g| glob_match(g, rel_path))
    }

    pub fn is_flat_dispatcher(&self, rel_path: &str) -> bool {
        self.flat_dispatcher_globs
            .iter()
            .any(|g| glob_match(g, rel_path))
    }

    pub fn layer_for(&self, rel_path: &str) -> Option<(usize, &str)> {
        for (idx, layer) in self.layers.iter().enumerate() {
            if layer.globs.iter().any(|g| glob_match(g, rel_path)) {
                return Some((idx, layer.name.as_str()));
            }
        }
        None
    }
}

fn validate_layer_rules(
    layers: &[LayerSpec],
    allowed_edges: &[LayerEdgeRule],
    forbidden_bypasses: &[LayerEdgeRule],
) -> Result<(), String> {
    let mut names: BTreeSet<&str> = BTreeSet::new();
    for layer in layers {
        let name = layer.name.trim();
        if name.is_empty() {
            return Err("invalid semantic-profile.json: layer name must not be empty".to_string());
        }
        if layer.globs.is_empty() {
            return Err(format!(
                "invalid semantic-profile.json: layer '{name}' must define at least one glob"
            ));
        }
        if layer.globs.iter().any(|g| g.trim().is_empty()) {
            return Err(format!(
                "invalid semantic-profile.json: layer '{name}' contains an empty glob"
            ));
        }
        if !names.insert(name) {
            return Err(format!(
                "invalid semantic-profile.json: duplicate layer name '{name}'"
            ));
        }
    }
    for (label, rules) in [
        ("allowed_edges", allowed_edges),
        ("forbidden_bypasses", forbidden_bypasses),
    ] {
        for rule in rules {
            if !names.contains(rule.from.as_str()) {
                return Err(format!(
                    "invalid semantic-profile.json: {label} references undeclared layer '{}'",
                    rule.from
                ));
            }
            if !names.contains(rule.to.as_str()) {
                return Err(format!(
                    "invalid semantic-profile.json: {label} references undeclared layer '{}'",
                    rule.to
                ));
            }
        }
    }
    Ok(())
}

/// Deterministic, polynomial-time, zero-regex portable glob matcher supporting `*`, `?`, and `**`.
pub fn glob_match(pattern: &str, path: &str) -> bool {
    let pat = pattern.replace('\\', "/");
    let text = path.replace('\\', "/");

    // Collapse adjacent `**` segments so pathological inputs stay linear in segment count.
    let mut pat_segs: Vec<&str> = Vec::new();
    for seg in pat.split('/') {
        if seg == "**" && pat_segs.last() == Some(&"**") {
            continue;
        }
        pat_segs.push(seg);
    }
    let txt_segs: Vec<&str> = text.split('/').collect();
    match_segments_dp(&pat_segs, &txt_segs)
}

fn match_segments_dp(pat: &[&str], txt: &[&str]) -> bool {
    let n = txt.len();
    let mut prev = vec![false; n + 1];
    let mut curr = vec![false; n + 1];
    prev[0] = true;

    for &p in pat {
        curr.fill(false);
        if p == "**" {
            let mut seen_true = false;
            for j in 0..=n {
                if prev[j] {
                    seen_true = true;
                }
                curr[j] = seen_true;
            }
        } else {
            for j in 1..=n {
                if prev[j - 1] && segment_match(p, txt[j - 1]) {
                    curr[j] = true;
                }
            }
        }
        std::mem::swap(&mut prev, &mut curr);
    }
    prev[n]
}

fn segment_match(pattern: &str, text: &str) -> bool {
    let p: Vec<char> = pattern.chars().collect();
    let t: Vec<char> = text.chars().collect();
    let (mut pi, mut ti) = (0usize, 0usize);
    let mut star_pi: Option<usize> = None;
    let mut star_ti: usize = 0;

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
