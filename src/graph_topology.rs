//! Relationship-topology analysis over the production import graph, write-sink
//! ownership map, declared stratum rules, and git co-change history, plus
//! portable typed graph-edge export (`--emit-graph-edges`).

use crate::model::{
    BypassFinding, CoChangePair, FileClassification, FileProfile, FileRole,
    GRAPH_EDGES_SCHEMA_VERSION, GraphEdge, GraphEdgesExport, GraphNode, NexusNode, PhantomCoupling,
    ReachInSignal, SccCluster, SmearedWriteTarget, Snapshot, TopologyReport,
    is_ephemeral_write_target,
};
use crate::profile_config::RepoProfile;
use std::collections::{BTreeMap, BTreeSet, VecDeque};
use std::path::{Path, PathBuf};

const MAX_PAIRWISE_SMEARED_WRITERS: usize = 16;

#[derive(Debug, Clone)]
pub struct ProductionGraph {
    pub adj: Vec<BTreeSet<usize>>,
    pub rev_adj: Vec<BTreeSet<usize>>,
    pub mod_adj: Vec<BTreeSet<usize>>,
}

struct GraphIndex {
    scopes: Vec<String>,
    scoped_path_map: BTreeMap<(String, String), Vec<usize>>,
    scoped_stem_map: BTreeMap<(String, String), Vec<usize>>,
    global_stem_map: BTreeMap<String, Vec<usize>>,
}

impl GraphIndex {
    fn build(files: &[FileProfile]) -> Self {
        let n = files.len();
        let mut scopes = Vec::with_capacity(n);
        let mut scoped_path_map: BTreeMap<(String, String), Vec<usize>> = BTreeMap::new();
        let mut scoped_stem_map: BTreeMap<(String, String), Vec<usize>> = BTreeMap::new();
        let mut global_stem_map: BTreeMap<String, Vec<usize>> = BTreeMap::new();

        for (idx, file) in files.iter().enumerate() {
            let scope = package_scope(&file.path);
            scopes.push(scope.clone());
            if file.role != FileRole::Production {
                continue;
            }
            for pkey in module_path_keys(&file.path, &scope) {
                scoped_path_map
                    .entry((scope.clone(), pkey))
                    .or_default()
                    .push(idx);
            }
            for stem in module_keys(&file.path) {
                scoped_stem_map
                    .entry((scope.clone(), stem.clone()))
                    .or_default()
                    .push(idx);
                global_stem_map.entry(stem).or_default().push(idx);
            }
        }

        Self {
            scopes,
            scoped_path_map,
            scoped_stem_map,
            global_stem_map,
        }
    }

    fn resolve_single_import(
        &self,
        raw_path: &str,
        src_rel_path: &str,
        scope: &str,
    ) -> Vec<usize> {
        if let Some(hit) = resolve_import_path(raw_path, src_rel_path, scope, &self.scoped_path_map)
        {
            return hit;
        }
        // Per-import stem fallback when path-based resolution did not match a module file.
        // Never fall back to `global_stem_map` for crate-anchored Rust paths (`crate/`, `self/`, `super/`)
        // so unresolved crate-local items cannot leak into cross-crate edges.
        let is_crate_anchored = raw_path.starts_with("crate/")
            || raw_path.starts_with("self/")
            || raw_path.starts_with("super/");
        if let Some(stem) = fallback_stem_from_path(raw_path) {
            if let Some(targets) = self.scoped_stem_map.get(&(scope.to_string(), stem.clone())) {
                return targets.clone();
            }
            if !is_crate_anchored
                && let Some(targets) = self.global_stem_map.get(&stem)
                && targets.len() == 1
            {
                return targets.clone();
            }
        }
        Vec::new()
    }

    fn resolve_mod_decl(
        &self,
        raw_path: &str,
        src_rel_path: &str,
        scope: &str,
    ) -> Vec<usize> {
        resolve_import_path(raw_path, src_rel_path, scope, &self.scoped_path_map)
            .unwrap_or_default()
    }
}

/// Build the package-scoped production import graph (`src -> dst`) with zero
/// cross-crate stem collisions in multi-package repositories, tracking structural
/// Rust `mod` declarations separately in `mod_adj` so idiomatic `mod child;` +
/// `use super::...` never forms a false dependency cycle.
pub fn build_import_graph(files: &[FileProfile]) -> ProductionGraph {
    let n = files.len();
    let mut adj: Vec<BTreeSet<usize>> = vec![BTreeSet::new(); n];
    let mut rev_adj: Vec<BTreeSet<usize>> = vec![BTreeSet::new(); n];
    let mut mod_adj: Vec<BTreeSet<usize>> = vec![BTreeSet::new(); n];
    let index = GraphIndex::build(files);

    for (src_idx, file) in files.iter().enumerate() {
        if file.role != FileRole::Production {
            continue;
        }
        let scope = &index.scopes[src_idx];

        for raw_mod in &file.mod_decl_paths {
            for dst_idx in index.resolve_mod_decl(raw_mod, &file.path, scope) {
                if dst_idx != src_idx {
                    mod_adj[src_idx].insert(dst_idx);
                }
            }
        }

        if !file.import_paths.is_empty() {
            for raw_path in &file.import_paths {
                for dst_idx in index.resolve_single_import(raw_path, &file.path, scope) {
                    if dst_idx != src_idx {
                        adj[src_idx].insert(dst_idx);
                        rev_adj[dst_idx].insert(src_idx);
                    }
                }
            }
        } else {
            // Backwards compatibility for legacy snapshots lacking `import_paths`.
            for imp in &file.internal_imports {
                if let Some(targets) = index.scoped_stem_map.get(&(scope.clone(), imp.clone())) {
                    for &dst_idx in targets {
                        if dst_idx != src_idx {
                            adj[src_idx].insert(dst_idx);
                            rev_adj[dst_idx].insert(src_idx);
                        }
                    }
                } else if let Some(targets) = index.global_stem_map.get(imp)
                    && targets.len() == 1
                {
                    let dst_idx = targets[0];
                    if dst_idx != src_idx {
                        adj[src_idx].insert(dst_idx);
                        rev_adj[dst_idx].insert(src_idx);
                    }
                }
            }
        }
    }

    ProductionGraph {
        adj,
        rev_adj,
        mod_adj,
    }
}

/// Resolve an import path (including Rust `crate/...`, `super/...`, `self/...`,
/// module-relative `./...`, and Python/TS relative paths) to the most specific
/// matching module file within the same package scope via longest-prefix matching.
fn resolve_import_path(
    raw_path: &str,
    src_rel_path: &str,
    scope: &str,
    scoped_path_map: &BTreeMap<(String, String), Vec<usize>>,
) -> Option<Vec<usize>> {
    let explicit_module_rel = raw_path.starts_with("./");
    let segs: Vec<&str> = raw_path
        .split('/')
        .filter(|s| !s.is_empty() && *s != ".")
        .collect();
    if segs.is_empty() {
        return None;
    }

    if explicit_module_rel {
        let mut base = current_module_dir_segments(src_rel_path, scope);
        for s in &segs {
            base.push((*s).to_string());
        }
        let refs: Vec<&str> = base.iter().map(String::as_str).collect();
        if let Some(hit) = longest_prefix_match(scope, &refs, scoped_path_map) {
            return Some(hit);
        }
        return longest_prefix_match(scope, &segs, scoped_path_map);
    }

    let resolved_segs: Vec<String> = match segs[0] {
        "crate" => segs[1..].iter().map(|s| (*s).to_string()).collect(),
        "super" | "self" => {
            // Exact Rust module-path semantics:
            //   `src/lib.rs`         -> []
            //   `src/foo/mod.rs`     -> ["foo"]
            //   `src/foo/bar.rs`     -> ["foo", "bar"]
            // `self` stays at the current module; each `super` pops one level.
            let mut base = current_module_path_segments(src_rel_path, scope);
            for &seg in &segs {
                match seg {
                    "self" => {}
                    "super" => {
                        base.pop();
                    }
                    other => base.push(other.to_string()),
                }
            }
            base
        }
        ".." => {
            let mut base = current_module_dir_segments(src_rel_path, scope);
            let mut idx = 0usize;
            while idx < segs.len() && segs[idx] == ".." {
                base.pop();
                idx += 1;
            }
            for s in &segs[idx..] {
                base.push((*s).to_string());
            }
            base
        }
        _ => {
            // Try direct scope-relative match first; if not found, try relative to current directory.
            if let Some(hit) = longest_prefix_match(scope, &segs, scoped_path_map) {
                return Some(hit);
            }
            let mut base = current_module_dir_segments(src_rel_path, scope);
            for s in &segs {
                base.push((*s).to_string());
            }
            base
        }
    };

    let refs: Vec<&str> = resolved_segs.iter().map(String::as_str).collect();
    longest_prefix_match(scope, &refs, scoped_path_map)
}

fn fallback_stem_from_path(raw_path: &str) -> Option<String> {
    let segs: Vec<&str> = raw_path
        .split('/')
        .filter(|s| !s.is_empty() && !matches!(*s, "." | ".." | "crate" | "super" | "self"))
        .collect();
    if segs.is_empty() {
        return None;
    }
    // Prefer the last lowercase/snake_case module segment (skipping trailing Capitalized Rust types).
    for &seg in segs.iter().rev() {
        if seg
            .chars()
            .next()
            .is_some_and(|c| c.is_ascii_lowercase() || c == '_')
        {
            return Some(seg.to_string());
        }
    }
    segs.last().map(|s| (*s).to_string())
}

fn longest_prefix_match(
    scope: &str,
    segs: &[&str],
    scoped_path_map: &BTreeMap<(String, String), Vec<usize>>,
) -> Option<Vec<usize>> {
    for len in (1..=segs.len()).rev() {
        let candidate = segs[..len].join("/");
        if let Some(targets) = scoped_path_map.get(&(scope.to_string(), candidate)) {
            return Some(targets.clone());
        }
    }
    None
}

fn current_module_dir_segments(rel_path: &str, scope: &str) -> Vec<String> {
    let trimmed = if !scope.is_empty()
        && let Some(rest) = rel_path.strip_prefix(scope)
    {
        rest.trim_start_matches('/')
    } else {
        rel_path
    };
    let trimmed = trimmed.strip_prefix("src/").unwrap_or(trimmed);
    let p = Path::new(trimmed);
    let Some(parent) = p.parent() else {
        return Vec::new();
    };
    parent
        .to_string_lossy()
        .replace('\\', "/")
        .split('/')
        .filter(|s| !s.is_empty())
        .map(String::from)
        .collect()
}

fn current_module_path_segments(rel_path: &str, scope: &str) -> Vec<String> {
    let mut segs = current_module_dir_segments(rel_path, scope);
    if !is_module_tree_root(rel_path)
        && let Some(stem) = Path::new(rel_path).file_stem().and_then(|s| s.to_str())
        && !stem.is_empty()
    {
        segs.push(stem.to_string());
    }
    segs
}

/// Populate per-file topology metrics (`layer`, `topology_role`, `nexus_score`,
/// `transitive_dependents`, `transitive_dependent_tokens`) and compute all 5
/// relationship-topology signals.
pub fn analyze_topology(
    files: &mut [FileProfile],
    graph: &ProductionGraph,
    co_change_pairs: &[CoChangePair],
    profile: &RepoProfile,
) -> TopologyReport {
    let n = files.len();

    // 1. Assign declared layers, topology roles, nexus scores, and transitive blast-radius.
    let mut layer_indices: Vec<Option<usize>> = vec![None; n];
    for (idx, file) in files.iter_mut().enumerate() {
        if file.role != FileRole::Production {
            file.layer = None;
            file.topology_role = "test_or_eval".to_string();
            file.nexus_score = 0;
            file.transitive_dependents = 0;
            file.transitive_dependent_tokens = 0;
            continue;
        }
        if let Some((lidx, lname)) = profile.layer_for(&file.path) {
            layer_indices[idx] = Some(lidx);
            file.layer = Some(lname.to_string());
        } else {
            file.layer = None;
        }
        file.nexus_score = file.fan_in.saturating_mul(file.fan_out);
        file.topology_role = classify_topology_role(file.fan_in, file.fan_out).to_string();
    }

    // Reuse one generation-stamped visited buffer and BFS queue across all nodes.
    let mut visited_gen: Vec<u32> = vec![0; n];
    let mut queue: VecDeque<usize> = VecDeque::new();
    let mut stamp: u32 = 0;

    for idx in 0..n {
        if files[idx].role != FileRole::Production {
            continue;
        }
        stamp = stamp.wrapping_add(1);
        if stamp == 0 {
            visited_gen.fill(0);
            stamp = 1;
        }
        let (dep_count, dep_tokens) =
            compute_transitive_dependents(idx, files, &graph.rev_adj, &mut visited_gen, stamp, &mut queue);
        files[idx].transitive_dependents = dep_count;
        files[idx].transitive_dependent_tokens = dep_tokens;
    }

    // 2. Tarjan Strongly Connected Components (|SCC| >= 2).
    let sccs = compute_tarjan_sccs(files, &graph.adj);

    // 3. Layer / Facade Bypasses, Stratum-Skipping Shortcuts & Cross-Boundary Reach-Ins.
    let bypasses = detect_bypasses(files, graph, &layer_indices, profile);

    // 4. Smeared Write Ownership (write sinks mutated by >= 2 distinct production modules).
    let smeared_writes = detect_smeared_writes(files);

    // 5. Spaghetti Nexus nodes (genuine hubs where fan_in > 0 && fan_out > 0).
    let mut top_nexus_nodes: Vec<NexusNode> = files
        .iter()
        .filter(|f| f.role == FileRole::Production && f.fan_in > 0 && f.fan_out > 0)
        .map(|f| NexusNode {
            path: f.path.clone(),
            fan_in: f.fan_in,
            fan_out: f.fan_out,
            nexus_score: f.nexus_score,
            transitive_dependents: f.transitive_dependents,
            transitive_dependent_tokens: f.transitive_dependent_tokens,
            layer: f.layer.clone(),
        })
        .collect();
    top_nexus_nodes.sort_by(|a, b| {
        b.nexus_score
            .cmp(&a.nexus_score)
            .then_with(|| b.transitive_dependent_tokens.cmp(&a.transitive_dependent_tokens))
            .then_with(|| b.transitive_dependents.cmp(&a.transitive_dependents))
            .then_with(|| a.path.cmp(&b.path))
    });

    // 6. Phantom Coupling (production git co-change pairs with >= 2 co-changes and zero direct import edge).
    let phantom_couplings = detect_phantom_couplings(files, graph, co_change_pairs);

    TopologyReport {
        sccs,
        bypasses,
        smeared_writes,
        top_nexus_nodes,
        phantom_couplings,
    }
}

/// Build the portable typed graph-edge export (`imports`, `bypasses`, `in_scc`,
/// `shares_write_target`, `phantom_cochanges`) plus node metadata ready for
/// graph-index or context-discovery ingestion.
pub fn export_graph_edges(snapshot: &Snapshot) -> GraphEdgesExport {
    let graph = build_import_graph(&snapshot.files);
    let index = GraphIndex::build(&snapshot.files);

    let mut file_to_scc: BTreeMap<&str, &str> = BTreeMap::new();
    for scc in &snapshot.topology.sccs {
        for f in &scc.files {
            file_to_scc.insert(f.as_str(), scc.id.as_str());
        }
    }

    let mut node_ids: BTreeSet<&str> = BTreeSet::new();
    let mut nodes: Vec<GraphNode> = snapshot
        .files
        .iter()
        .filter(|f| f.role == FileRole::Production)
        .map(|f| {
            node_ids.insert(f.path.as_str());
            GraphNode {
                id: f.path.clone(),
                language: f.language,
                role: f.role,
                layer: f.layer.clone(),
                topology_role: if f.topology_role.is_empty() {
                    classify_topology_role(f.fan_in, f.fan_out).to_string()
                } else {
                    f.topology_role.clone()
                },
                prod_loc: f.prod_loc,
                est_tokens: f.est_tokens,
                fan_in: f.fan_in,
                fan_out: f.fan_out,
                nexus_score: f.nexus_score,
                transitive_dependents: f.transitive_dependents,
                transitive_dependent_tokens: f.transitive_dependent_tokens,
                scc_id: file_to_scc.get(f.path.as_str()).map(|s| (*s).to_string()),
                hotspot_score: f.hotspot_score,
            }
        })
        .collect();
    nodes.sort_by(|a, b| a.id.cmp(&b.id));

    let mut edges: Vec<GraphEdge> = Vec::new();
    let mut seen_edges: BTreeSet<(String, String, String, Option<String>)> = BTreeSet::new();

    let mut push_edge = |kind: &str, from: String, to: String, weight: usize, label: Option<String>| {
        if seen_edges.insert((kind.to_string(), from.clone(), to.clone(), label.clone())) {
            edges.push(GraphEdge {
                kind: kind.to_string(),
                from,
                to,
                weight,
                label,
            });
        }
    };

    // 1. Direct production `imports` edges and `in_scc` cycle edges.
    for (src_idx, dsts) in graph.adj.iter().enumerate() {
        let Some(src_file) = snapshot.files.get(src_idx) else {
            continue;
        };
        if src_file.role != FileRole::Production {
            continue;
        }
        let src_scc = file_to_scc.get(src_file.path.as_str()).copied();
        for &dst_idx in dsts {
            let Some(dst_file) = snapshot.files.get(dst_idx) else {
                continue;
            };
            push_edge(
                "imports",
                src_file.path.clone(),
                dst_file.path.clone(),
                1,
                None,
            );
            if let (Some(a_scc), Some(b_scc)) =
                (src_scc, file_to_scc.get(dst_file.path.as_str()).copied())
                && a_scc == b_scc
            {
                push_edge(
                    "in_scc",
                    src_file.path.clone(),
                    dst_file.path.clone(),
                    1,
                    Some(a_scc.to_string()),
                );
            }
        }
    }

    // 1b. Structural Rust external module declarations (`declares_mod`).
    for (src_idx, dsts) in graph.mod_adj.iter().enumerate() {
        let Some(src_file) = snapshot.files.get(src_idx) else {
            continue;
        };
        if src_file.role != FileRole::Production {
            continue;
        }
        for &dst_idx in dsts {
            let Some(dst_file) = snapshot.files.get(dst_idx) else {
                continue;
            };
            push_edge(
                "declares_mod",
                src_file.path.clone(),
                dst_file.path.clone(),
                1,
                None,
            );
        }
    }

    // 2. `bypasses` edges (resolving reach-in symbol/path targets to production GraphNode.id when possible).
    for bypass in &snapshot.topology.bypasses {
        let (resolved_to, edge_label) = if node_ids.contains(bypass.to.as_str()) {
            (bypass.to.clone(), bypass.kind.clone())
        } else if let Some(node_id) =
            resolve_bypass_target_to_node(&bypass.from, &bypass.to, &snapshot.files, &index)
        {
            (node_id, format!("{}:{}", bypass.kind, bypass.to))
        } else {
            (bypass.to.clone(), bypass.kind.clone())
        };
        push_edge(
            "bypasses",
            bypass.from.clone(),
            resolved_to,
            1,
            Some(edge_label),
        );
    }

    // 3. `shares_write_target` edges.
    for smeared in &snapshot.topology.smeared_writes {
        let w = &smeared.writers;
        if w.len() <= MAX_PAIRWISE_SMEARED_WRITERS {
            for i in 0..w.len() {
                for j in (i + 1)..w.len() {
                    push_edge(
                        "shares_write_target",
                        w[i].clone(),
                        w[j].clone(),
                        smeared.writer_count,
                        Some(smeared.target.clone()),
                    );
                }
            }
        } else if let Some(anchor) = w.first() {
            for peer in w.iter().skip(1) {
                push_edge(
                    "shares_write_target",
                    anchor.clone(),
                    peer.clone(),
                    smeared.writer_count,
                    Some(smeared.target.clone()),
                );
            }
        }
    }

    // 4. `phantom_cochanges` edges.
    for phantom in &snapshot.topology.phantom_couplings {
        push_edge(
            "phantom_cochanges",
            phantom.file_a.clone(),
            phantom.file_b.clone(),
            phantom.co_changes,
            Some("phantom_cochange".to_string()),
        );
    }

    edges.sort_by(|a, b| {
        a.kind
            .cmp(&b.kind)
            .then_with(|| a.from.cmp(&b.from))
            .then_with(|| a.to.cmp(&b.to))
            .then_with(|| a.label.cmp(&b.label))
    });

    GraphEdgesExport {
        schema_version: GRAPH_EDGES_SCHEMA_VERSION,
        repo_label: snapshot.repo_label.clone(),
        commit: snapshot.commit.clone(),
        node_count: nodes.len(),
        edge_count: edges.len(),
        nodes,
        edges,
    }
}

fn resolve_bypass_target_to_node(
    from_path: &str,
    raw_target: &str,
    files: &[FileProfile],
    index: &GraphIndex,
) -> Option<String> {
    let scope = package_scope(from_path);
    let normalized = if raw_target.contains("::") {
        raw_target.replace("::", "/")
    } else if raw_target.contains('/') || raw_target.contains('\\') || raw_target.ends_with(".rs") {
        let cleaned = raw_target
            .replace('\\', "/")
            .trim_end_matches(".rs")
            .trim_end_matches(".py")
            .trim_end_matches(".ts")
            .trim_end_matches(".tsx")
            .trim_end_matches(".js")
            .trim_end_matches(".mjs")
            .to_string();
        let cleaned = cleaned.strip_suffix("/mod").unwrap_or(&cleaned);
        if cleaned.starts_with("../") || cleaned.starts_with("./") {
            cleaned.to_string()
        } else {
            format!("./{cleaned}")
        }
    } else {
        raw_target.replace('.', "/")
    };

    let candidates = index.resolve_single_import(&normalized, from_path, &scope);
    for idx in candidates {
        if let Some(f) = files.get(idx)
            && f.role == FileRole::Production
            && f.path != from_path
        {
            return Some(f.path.clone());
        }
    }
    None
}

pub fn cap_topology_for_packet(topology: &TopologyReport, top_k: usize) -> TopologyReport {
    TopologyReport {
        sccs: topology.sccs.iter().take(top_k).cloned().collect(),
        bypasses: topology.bypasses.iter().take(top_k).cloned().collect(),
        smeared_writes: topology.smeared_writes.iter().take(top_k).cloned().collect(),
        top_nexus_nodes: topology.top_nexus_nodes.iter().take(top_k).cloned().collect(),
        phantom_couplings: topology
            .phantom_couplings
            .iter()
            .take(top_k)
            .cloned()
            .collect(),
    }
}

fn classify_topology_role(fan_in: usize, fan_out: usize) -> &'static str {
    match (fan_in, fan_out) {
        (0, 0) => "isolated",
        (0, _) => "composition_root",
        (_, 0) => "leaf_utility",
        (_, _) => "hub",
    }
}

fn compute_transitive_dependents(
    start: usize,
    files: &[FileProfile],
    rev_adj: &[BTreeSet<usize>],
    visited_gen: &mut [u32],
    stamp: u32,
    queue: &mut VecDeque<usize>,
) -> (usize, usize) {
    queue.clear();
    visited_gen[start] = stamp;
    queue.push_back(start);

    let mut count = 0usize;
    let mut tokens = 0usize;
    while let Some(cur) = queue.pop_front() {
        for &parent in &rev_adj[cur] {
            if visited_gen[parent] != stamp && files[parent].role == FileRole::Production {
                visited_gen[parent] = stamp;
                count += 1;
                tokens = tokens.saturating_add(files[parent].est_tokens);
                queue.push_back(parent);
            }
        }
    }
    (count, tokens)
}

fn compute_tarjan_sccs(files: &[FileProfile], adj: &[BTreeSet<usize>]) -> Vec<SccCluster> {
    let n = files.len();
    let mut index_counter = 0usize;
    let mut indices: Vec<Option<usize>> = vec![None; n];
    let mut lowlink: Vec<usize> = vec![0; n];
    let mut on_stack: Vec<bool> = vec![false; n];
    let mut stack: Vec<usize> = Vec::new();
    let mut raw_sccs: Vec<Vec<usize>> = Vec::new();

    // Iterative Tarjan DFS so arbitrarily deep import chains never overflow the call stack.
    for start in 0..n {
        if files[start].role != FileRole::Production || indices[start].is_some() {
            continue;
        }
        let mut call_stack: Vec<(usize, Vec<usize>, usize)> = Vec::new();
        indices[start] = Some(index_counter);
        lowlink[start] = index_counter;
        index_counter += 1;
        stack.push(start);
        on_stack[start] = true;
        let neighbors: Vec<usize> = adj[start].iter().copied().collect();
        call_stack.push((start, neighbors, 0));

        while let Some(frame) = call_stack.last_mut() {
            let v = frame.0;
            if frame.2 < frame.1.len() {
                let w = frame.1[frame.2];
                frame.2 += 1;
                if files[w].role != FileRole::Production {
                    continue;
                }
                if indices[w].is_none() {
                    indices[w] = Some(index_counter);
                    lowlink[w] = index_counter;
                    index_counter += 1;
                    stack.push(w);
                    on_stack[w] = true;
                    let w_neighbors: Vec<usize> = adj[w].iter().copied().collect();
                    call_stack.push((w, w_neighbors, 0));
                } else if on_stack[w]
                    && let Some(w_idx) = indices[w]
                {
                    lowlink[v] = lowlink[v].min(w_idx);
                }
            } else {
                let finished_v = v;
                let finished_low = lowlink[finished_v];
                let finished_idx = indices[finished_v].unwrap_or(0);
                call_stack.pop();

                if let Some(parent_frame) = call_stack.last() {
                    let p = parent_frame.0;
                    lowlink[p] = lowlink[p].min(finished_low);
                }

                if finished_low == finished_idx {
                    let mut component = Vec::new();
                    while let Some(w) = stack.pop() {
                        on_stack[w] = false;
                        component.push(w);
                        if w == finished_v {
                            break;
                        }
                    }
                    if component.len() >= 2 {
                        raw_sccs.push(component);
                    }
                }
            }
        }
    }

    let mut clusters: Vec<SccCluster> = raw_sccs
        .into_iter()
        .map(|comp| {
            let mut file_paths: Vec<String> = comp
                .iter()
                .map(|&i| files[i].path.clone())
                .collect();
            file_paths.sort();
            let total_prod_loc: usize = comp.iter().map(|&i| files[i].prod_loc).sum();
            let total_est_tokens: usize = comp.iter().map(|&i| files[i].est_tokens).sum();
            SccCluster {
                id: String::new(),
                files: file_paths,
                total_prod_loc,
                total_est_tokens,
            }
        })
        .collect();

    clusters.sort_by(|a, b| {
        b.total_est_tokens
            .cmp(&a.total_est_tokens)
            .then_with(|| b.files.len().cmp(&a.files.len()))
            .then_with(|| a.files.cmp(&b.files))
    });
    for (idx, cluster) in clusters.iter_mut().enumerate() {
        cluster.id = format!("scc-{}", idx + 1);
    }
    clusters
}

fn detect_bypasses(
    files: &[FileProfile],
    graph: &ProductionGraph,
    layer_indices: &[Option<usize>],
    profile: &RepoProfile,
) -> Vec<BypassFinding> {
    let mut findings: Vec<BypassFinding> = Vec::new();
    let mut seen: BTreeSet<(String, String, String)> = BTreeSet::new();

    let mut push_finding = |finding: BypassFinding| {
        let key = (
            finding.kind.clone(),
            finding.from.clone(),
            finding.to.clone(),
        );
        if seen.insert(key) {
            findings.push(finding);
        }
    };

    // 1. Declared stratum / layer boundary violations from semantic-profile.json.
    if !profile.layers.is_empty() {
        for (src_idx, dsts) in graph.adj.iter().enumerate() {
            let Some(src_lidx) = layer_indices[src_idx] else {
                continue;
            };
            let src_layer = profile.layers[src_lidx].name.as_str();
            let src_path = &files[src_idx].path;

            for &dst_idx in dsts {
                let Some(dst_lidx) = layer_indices[dst_idx] else {
                    continue;
                };
                if src_lidx == dst_lidx {
                    continue;
                }
                let dst_layer = profile.layers[dst_lidx].name.as_str();
                let dst_path = &files[dst_idx].path;

                let is_forbidden = profile
                    .forbidden_bypasses
                    .iter()
                    .any(|r| r.from == src_layer && r.to == dst_layer);
                if is_forbidden {
                    push_finding(BypassFinding {
                        kind: "declared_forbidden_bypass".to_string(),
                        from: src_path.clone(),
                        via: None,
                        to: dst_path.clone(),
                        detail: format!(
                            "forbidden layer bypass '{src_layer}' -> '{dst_layer}' declared in semantic-profile.json"
                        ),
                    });
                    continue;
                }

                if !profile.allowed_edges.is_empty() {
                    let is_allowed = profile
                        .allowed_edges
                        .iter()
                        .any(|r| r.from == src_layer && r.to == dst_layer);
                    if !is_allowed && !is_exempt_leaf_target(&files[dst_idx], profile) {
                        push_finding(BypassFinding {
                            kind: "declared_stratum_violation".to_string(),
                            from: src_path.clone(),
                            via: None,
                            to: dst_path.clone(),
                            detail: format!(
                                "edge '{src_layer}' -> '{dst_layer}' is not listed in allowed_edges"
                            ),
                        });
                    }
                } else if profile.forbidden_bypasses.is_empty()
                    && profile.layers.len() >= 2
                    && !is_exempt_leaf_target(&files[dst_idx], profile)
                {
                    if dst_lidx < src_lidx {
                        push_finding(BypassFinding {
                            kind: "declared_stratum_violation".to_string(),
                            from: src_path.clone(),
                            via: None,
                            to: dst_path.clone(),
                            detail: format!(
                                "upward layer inversion '{src_layer}' -> '{dst_layer}' violates declared layer order"
                            ),
                        });
                    } else if profile.layers.len() >= 3 && dst_lidx > src_lidx + 1 {
                        let skipped: Vec<&str> = profile.layers[(src_lidx + 1)..dst_lidx]
                            .iter()
                            .map(|l| l.name.as_str())
                            .collect();
                        push_finding(BypassFinding {
                            kind: "declared_stratum_violation".to_string(),
                            from: src_path.clone(),
                            via: None,
                            to: dst_path.clone(),
                            detail: format!(
                                "stratum-skipping shortcut '{src_layer}' -> '{dst_layer}' skips [{}]",
                                skipped.join(", ")
                            ),
                        });
                    }
                }
            }
        }
    }

    // 2. Shortcut triangles: A -> B -> C alongside direct A -> C into an internal non-leaf module.
    //    Intersect the smaller adjacency set of (dsts, adj[b]) for O(E * min(d+, alpha) log V) scaling.
    for (a, dsts) in graph.adj.iter().enumerate() {
        if files[a].role != FileRole::Production || is_module_tree_root(&files[a].path) {
            continue;
        }
        let mut via_by_target: BTreeMap<usize, Vec<&str>> = BTreeMap::new();
        for &b in dsts {
            if files[b].role != FileRole::Production || is_module_tree_root(&files[b].path) {
                continue;
            }
            let b_adj = &graph.adj[b];
            let (smaller, larger) = if dsts.len() <= b_adj.len() {
                (dsts, b_adj)
            } else {
                (b_adj, dsts)
            };
            for &c in smaller {
                if c == b || c == a || !larger.contains(&c) {
                    continue;
                }
                if files[c].role != FileRole::Production
                    || is_exempt_leaf_target(&files[c], profile)
                    || is_direct_parent_index(&files[a].path, &files[c].path)
                {
                    continue;
                }
                via_by_target
                    .entry(c)
                    .or_default()
                    .push(files[b].path.as_str());
            }
        }

        for (c, mut intermediaries) in via_by_target {
            intermediaries.sort_unstable();
            let primary_via = intermediaries[0].to_string();
            let extra = if intermediaries.len() > 1 {
                format!(" (+{} more)", intermediaries.len() - 1)
            } else {
                String::new()
            };
            push_finding(BypassFinding {
                kind: "shortcut_triangle".to_string(),
                from: files[a].path.clone(),
                via: Some(primary_via.clone()),
                to: files[c].path.clone(),
                detail: format!(
                    "direct shortcut {} -> {} bypasses intermediary {primary_via}{extra} into non-leaf module (fan_out={})",
                    files[a].path, files[c].path, files[c].fan_out
                ),
            });
        }
    }

    // 3. Cross-boundary reach-ins (`#[path = "..."]`, `_private` helper/module imports, deep internal imports).
    for file in files {
        if file.role != FileRole::Production {
            continue;
        }
        for ri in &file.reach_ins {
            if is_exempt_direct_sibling_reexport(&file.path, ri) {
                continue;
            }
            push_finding(BypassFinding {
                kind: "cross_boundary_reach_in".to_string(),
                from: file.path.clone(),
                via: None,
                to: ri.target.clone(),
                detail: format!("{} at line {} targets '{}'", ri.kind, ri.line, ri.target),
            });
        }
    }

    findings.sort_by(|a, b| {
        a.kind
            .cmp(&b.kind)
            .then_with(|| a.from.cmp(&b.from))
            .then_with(|| a.to.cmp(&b.to))
    });
    findings
}

/// Exempt only direct-sibling private re-exports from a package/module index file
/// (`self::_child`, 2-segment `crate::_child` inside `lib.rs`, direct `_child` in `__init__.py`,
/// and direct `./_child` in `index.{ts,js}`). `#[path = "..."]` is never exempted.
fn is_exempt_direct_sibling_reexport(rel_path: &str, ri: &ReachInSignal) -> bool {
    if ri.kind == "rust_path_attr" {
        return false;
    }
    let file_name = Path::new(rel_path)
        .file_name()
        .and_then(|s| s.to_str())
        .unwrap_or("");
    match file_name {
        "lib.rs" => {
            let segs: Vec<&str> = ri.target.split("::").collect();
            segs.len() == 2 && matches!(segs[0], "self" | "crate")
        }
        "mod.rs" => {
            let segs: Vec<&str> = ri.target.split("::").collect();
            segs.len() == 2 && segs[0] == "self"
        }
        "__init__.py" => {
            !ri.target.contains('/') && !ri.target.contains('.') && !ri.target.contains("::")
        }
        "index.ts" | "index.js" => {
            ri.target
                .strip_prefix("./")
                .is_some_and(|rest| !rest.is_empty() && !rest.contains('/'))
        }
        _ => false,
    }
}

fn is_exempt_leaf_target(file: &FileProfile, profile: &RepoProfile) -> bool {
    if file.fan_out == 0 {
        return true;
    }
    if file.classification == FileClassification::StaticDataTable
        || profile.is_cohesive_data(&file.path)
    {
        return true;
    }
    false
}

fn is_module_tree_root(rel_path: &str) -> bool {
    let p = Path::new(rel_path);
    matches!(
        p.file_name().and_then(|s| s.to_str()),
        Some("lib.rs" | "main.rs" | "mod.rs" | "__init__.py" | "index.ts" | "index.js")
    )
}

fn is_direct_parent_index(parent_path: &str, child_path: &str) -> bool {
    if is_module_tree_root(parent_path) {
        let parent_dir = Path::new(parent_path).parent();
        let child_dir = Path::new(child_path).parent();
        if parent_dir.is_some() && parent_dir == child_dir {
            return true;
        }
        if is_module_tree_root(child_path)
            && let Some(child_parent_dir) = child_dir.and_then(|d| d.parent())
            && parent_dir == Some(child_parent_dir)
        {
            return true;
        }
    }
    // Rust 2018 module root `src/<dir>.rs` declaring children in `src/<dir>/*.rs` or `src/<dir>/<sub >/mod.rs`.
    let p = Path::new(parent_path);
    if p.extension().and_then(|s| s.to_str()) == Some("rs")
        && let Some(stem) = p.file_stem().and_then(|s| s.to_str())
    {
        let expected_dir = match p.parent() {
            Some(dir) if !dir.as_os_str().is_empty() => dir.join(stem),
            _ => PathBuf::from(stem),
        };
        let child_p = Path::new(child_path);
        if child_p.parent() == Some(expected_dir.as_path()) {
            return true;
        }
        if is_module_tree_root(child_path)
            && child_p.parent().and_then(|d| d.parent()) == Some(expected_dir.as_path())
        {
            return true;
        }
    }
    false
}

fn detect_smeared_writes(files: &[FileProfile]) -> Vec<SmearedWriteTarget> {
    let mut by_target: BTreeMap<String, (BTreeSet<String>, BTreeSet<String>)> = BTreeMap::new();
    for file in files {
        if file.role != FileRole::Production {
            continue;
        }
        for hit in &file.write_targets {
            if is_ephemeral_write_target(&hit.target) {
                continue;
            }
            let entry = by_target.entry(hit.target.clone()).or_default();
            entry.0.insert(file.path.clone());
            entry.1.insert(hit.sink.clone());
        }
    }

    let mut smeared: Vec<SmearedWriteTarget> = by_target
        .into_iter()
        .filter(|(_, (writers, _))| writers.len() >= 2)
        .map(|(target, (writers, sinks))| {
            let writer_list: Vec<String> = writers.into_iter().collect();
            let sink_list: Vec<String> = sinks.into_iter().collect();
            SmearedWriteTarget {
                target,
                writer_count: writer_list.len(),
                writers: writer_list,
                sinks: sink_list,
            }
        })
        .collect();

    smeared.sort_by(|a, b| {
        b.writer_count
            .cmp(&a.writer_count)
            .then_with(|| a.target.cmp(&b.target))
    });
    smeared
}

fn detect_phantom_couplings(
    files: &[FileProfile],
    graph: &ProductionGraph,
    co_change_pairs: &[CoChangePair],
) -> Vec<PhantomCoupling> {
    let path_to_idx: BTreeMap<&str, usize> = files
        .iter()
        .enumerate()
        .filter(|(_, f)| f.role == FileRole::Production)
        .map(|(idx, f)| (f.path.as_str(), idx))
        .collect();

    let mut phantoms = Vec::new();
    for pair in co_change_pairs {
        if pair.co_changes < 2 {
            continue;
        }
        let (Some(&idx_a), Some(&idx_b)) = (
            path_to_idx.get(pair.file_a.as_str()),
            path_to_idx.get(pair.file_b.as_str()),
        ) else {
            continue;
        };
        let has_direct_edge = graph.adj[idx_a].contains(&idx_b)
            || graph.adj[idx_b].contains(&idx_a)
            || graph.mod_adj[idx_a].contains(&idx_b)
            || graph.mod_adj[idx_b].contains(&idx_a);
        if !has_direct_edge {
            phantoms.push(PhantomCoupling {
                file_a: pair.file_a.clone(),
                file_b: pair.file_b.clone(),
                co_changes: pair.co_changes,
                combined_est_tokens: files[idx_a]
                    .est_tokens
                    .saturating_add(files[idx_b].est_tokens),
            });
        }
    }

    phantoms.sort_by(|a, b| {
        b.co_changes
            .cmp(&a.co_changes)
            .then_with(|| b.combined_est_tokens.cmp(&a.combined_est_tokens))
            .then_with(|| a.file_a.cmp(&b.file_a))
            .then_with(|| a.file_b.cmp(&b.file_b))
    });
    phantoms
}

fn package_scope(rel_path: &str) -> String {
    if let Some((prefix, _)) = rel_path.split_once("/src/") {
        return prefix.to_string();
    }
    if rel_path.starts_with("src/") {
        return String::new();
    }
    if let Some((top, _)) = rel_path.split_once('/') {
        return top.to_string();
    }
    String::new()
}

fn module_path_keys(rel_path: &str, scope: &str) -> Vec<String> {
    let trimmed = if !scope.is_empty()
        && let Some(rest) = rel_path.strip_prefix(scope)
    {
        rest.trim_start_matches('/')
    } else {
        rel_path
    };
    let trimmed = trimmed.strip_prefix("src/").unwrap_or(trimmed);
    let p = Path::new(trimmed);
    let mut keys = Vec::new();
    let stem = p.file_stem().and_then(|s| s.to_str()).unwrap_or("");
    if stem == "mod" || stem == "__init__" || stem == "index" {
        if let Some(parent) = p.parent() {
            let s = parent.to_string_lossy().replace('\\', "/");
            if !s.is_empty() {
                keys.push(s);
            }
        }
    } else if !stem.is_empty() {
        let without_ext = match p.parent() {
            Some(parent) if !parent.as_os_str().is_empty() => {
                format!("{}/{stem}", parent.to_string_lossy().replace('\\', "/"))
            }
            _ => stem.to_string(),
        };
        keys.push(without_ext);
    }
    keys
}

pub fn module_keys(rel_path: &str) -> Vec<String> {
    let p = Path::new(rel_path);
    let mut keys = Vec::new();
    if let Some(stem) = p.file_stem().and_then(|s| s.to_str()) {
        if stem == "mod" || stem == "__init__" || stem == "index" {
            if let Some(parent_name) = p.parent().and_then(|d| d.file_name()).and_then(|s| s.to_str())
            {
                keys.push(parent_name.to_string());
            }
        } else {
            keys.push(stem.to_string());
        }
    }
    keys
}
