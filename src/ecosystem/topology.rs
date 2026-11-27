//! Cross-repo topology analysis: iterative Tarjan SCC detection, fan-in/fan-out,
//! transitive blast radius, and shortest-path impact reports.

use crate::ecosystem::model::{
    EcosystemEdge, EcosystemRepoNode, EcosystemScc, ImpactPath, ImpactReport,
};
use std::collections::{BTreeMap, BTreeSet, VecDeque};

/// Compute repo-level Tarjan SCCs (`|SCC| >= 2`), populate per-repo `fan_in`, `fan_out`,
/// `scc_id`, and `transitive_dependents`, and return deterministically sorted SCCs.
pub fn analyze_ecosystem_topology(
    nodes: &mut [EcosystemRepoNode],
    edges: &[EcosystemEdge],
) -> Vec<EcosystemScc> {
    let n = nodes.len();
    let id_to_idx: BTreeMap<String, usize> = nodes
        .iter()
        .enumerate()
        .map(|(i, node)| (node.id.clone(), i))
        .collect();

    let mut adj: Vec<BTreeSet<usize>> = vec![BTreeSet::new(); n];
    let mut rev_adj: Vec<BTreeSet<usize>> = vec![BTreeSet::new(); n];

    for edge in edges {
        if let (Some(&src), Some(&dst)) = (id_to_idx.get(&edge.from), id_to_idx.get(&edge.to))
            && src != dst
        {
            adj[src].insert(dst);
            rev_adj[dst].insert(src);
        }
    }

    let raw_sccs = tarjan_sccs(n, &adj);
    let mut sccs: Vec<EcosystemScc> = Vec::with_capacity(raw_sccs.len());

    let mut member_lists: Vec<Vec<usize>> = raw_sccs
        .into_iter()
        .filter(|comp| comp.len() >= 2)
        .map(|mut comp| {
            comp.sort_by(|&a, &b| nodes[a].id.cmp(&nodes[b].id));
            comp
        })
        .collect();
    member_lists.sort_by(|a, b| nodes[a[0]].id.cmp(&nodes[b[0]].id));

    let mut node_to_scc: Vec<Option<String>> = vec![None; n];
    for (idx, comp) in member_lists.into_iter().enumerate() {
        let scc_id = format!("scc-{}", idx + 1);
        let member_set: BTreeSet<usize> = comp.iter().copied().collect();
        let mut internal_edges = 0usize;
        for &u in &comp {
            node_to_scc[u] = Some(scc_id.clone());
            for &v in &adj[u] {
                if member_set.contains(&v) {
                    internal_edges += 1;
                }
            }
        }
        let repos = comp.into_iter().map(|i| nodes[i].id.clone()).collect();
        sccs.push(EcosystemScc {
            id: scc_id,
            repos,
            edge_count: internal_edges,
        });
    }

    for (i, node) in nodes.iter_mut().enumerate() {
        node.fan_out = adj[i].len();
        node.fan_in = rev_adj[i].len();
        node.scc_id = node_to_scc[i].clone();
    }

    for i in 0..n {
        let dependents = reverse_bfs_ids(i, &rev_adj, nodes);
        nodes[i].transitive_dependent_count = dependents.len();
        nodes[i].transitive_dependents = dependents;
    }

    sccs
}

/// Build an impact report showing direct & transitive dependents, shortest impact paths,
/// direct upstream dependencies, and SCC peers for `target_query`.
pub fn build_impact_report(
    target_query: &str,
    nodes: &[EcosystemRepoNode],
    edges: &[EcosystemEdge],
    sccs: &[EcosystemScc],
) -> Result<ImpactReport, String> {
    let target_idx = resolve_target_repo(target_query, nodes)?;
    let n = nodes.len();
    let id_to_idx: BTreeMap<&str, usize> = nodes
        .iter()
        .enumerate()
        .map(|(i, node)| (node.id.as_str(), i))
        .collect();

    let mut adj: Vec<BTreeSet<usize>> = vec![BTreeSet::new(); n];
    let mut rev_adj: Vec<BTreeSet<usize>> = vec![BTreeSet::new(); n];
    for edge in edges {
        if let (Some(&src), Some(&dst)) = (
            id_to_idx.get(edge.from.as_str()),
            id_to_idx.get(edge.to.as_str()),
        ) && src != dst
        {
            adj[src].insert(dst);
            rev_adj[dst].insert(src);
        }
    }

    let target_id = nodes[target_idx].id.clone();
    let mut direct_dependents: Vec<String> = rev_adj[target_idx]
        .iter()
        .map(|&i| nodes[i].id.clone())
        .collect();
    direct_dependents.sort();

    let mut direct_dependencies: Vec<String> = adj[target_idx]
        .iter()
        .map(|&i| nodes[i].id.clone())
        .collect();
    direct_dependencies.sort();

    // Deterministic BFS from target along reverse edges to capture shortest impact chains.
    let mut parent: Vec<Option<usize>> = vec![None; n];
    let mut visited = vec![false; n];
    let mut queue = VecDeque::new();
    visited[target_idx] = true;
    queue.push_back(target_idx);

    let mut reached = Vec::new();
    while let Some(cur) = queue.pop_front() {
        let mut next_nodes: Vec<usize> = rev_adj[cur].iter().copied().collect();
        next_nodes.sort_by(|&a, &b| nodes[a].id.cmp(&nodes[b].id));
        for dep_idx in next_nodes {
            if !visited[dep_idx] {
                visited[dep_idx] = true;
                parent[dep_idx] = Some(cur);
                reached.push(dep_idx);
                queue.push_back(dep_idx);
            }
        }
    }

    reached.sort_by(|&a, &b| nodes[a].id.cmp(&nodes[b].id));
    let transitive_dependents: Vec<String> =
        reached.iter().map(|&i| nodes[i].id.clone()).collect();
    let mut impact_paths = Vec::with_capacity(reached.len());
    for &dep_idx in &reached {
        let mut chain = Vec::new();
        let mut cur = Some(dep_idx);
        while let Some(idx) = cur {
            chain.push(nodes[idx].id.clone());
            cur = parent[idx];
        }
        chain.reverse();
        impact_paths.push(ImpactPath {
            repo: nodes[dep_idx].id.clone(),
            path: chain,
        });
    }

    let scc_members = nodes[target_idx]
        .scc_id
        .as_deref()
        .and_then(|sid| sccs.iter().find(|s| s.id == sid))
        .map(|scc| {
            scc.repos
                .iter()
                .filter(|r| *r != &target_id)
                .cloned()
                .collect()
        })
        .unwrap_or_default();

    Ok(ImpactReport {
        target_repo: target_id,
        direct_dependents,
        transitive_dependent_count: transitive_dependents.len(),
        transitive_dependents,
        direct_dependencies,
        impact_paths,
        scc_members,
    })
}

fn resolve_target_repo(query: &str, nodes: &[EcosystemRepoNode]) -> Result<usize, String> {
    let trimmed = query.trim();
    if let Some(pos) = nodes.iter().position(|n| n.id == trimmed) {
        return Ok(pos);
    }
    let by_name: Vec<usize> = nodes
        .iter()
        .enumerate()
        .filter(|(_, n)| n.name == trimmed)
        .map(|(i, _)| i)
        .collect();
    if by_name.len() == 1 {
        return Ok(by_name[0]);
    }
    if by_name.len() > 1 {
        let ids: Vec<&str> = by_name.iter().map(|&i| nodes[i].id.as_str()).collect();
        return Err(format!(
            "ambiguous --impact target '{trimmed}': matches multiple repos ({})",
            ids.join(", ")
        ));
    }
    let by_pkg: Vec<usize> = nodes
        .iter()
        .enumerate()
        .filter(|(_, n)| n.packages.iter().any(|p| p.name == trimmed))
        .map(|(i, _)| i)
        .collect();
    if by_pkg.len() == 1 {
        return Ok(by_pkg[0]);
    }
    if by_pkg.len() > 1 {
        let ids: Vec<&str> = by_pkg.iter().map(|&i| nodes[i].id.as_str()).collect();
        return Err(format!(
            "ambiguous --impact target '{trimmed}': matches multiple repos ({})",
            ids.join(", ")
        ));
    }
    Err(format!(
        "impact target '{trimmed}' not found among {} discovered repositories",
        nodes.len()
    ))
}

fn reverse_bfs_ids(
    start: usize,
    rev_adj: &[BTreeSet<usize>],
    nodes: &[EcosystemRepoNode],
) -> Vec<String> {
    let mut visited = vec![false; nodes.len()];
    let mut queue = VecDeque::new();
    visited[start] = true;
    queue.push_back(start);

    let mut out = Vec::new();
    while let Some(cur) = queue.pop_front() {
        for &dep in &rev_adj[cur] {
            if !visited[dep] {
                visited[dep] = true;
                out.push(nodes[dep].id.clone());
                queue.push_back(dep);
            }
        }
    }
    out.sort();
    out
}

/// Iterative Tarjan's strongly connected components algorithm (no recursion limit risk).
fn tarjan_sccs(n: usize, adj: &[BTreeSet<usize>]) -> Vec<Vec<usize>> {
    struct Frame {
        node: usize,
        neighbors: Vec<usize>,
        next_edge: usize,
    }

    let mut index_counter = 0usize;
    let mut indices: Vec<Option<usize>> = vec![None; n];
    let mut lowlink: Vec<usize> = vec![0; n];
    let mut on_stack: Vec<bool> = vec![false; n];
    let mut tarjan_stack: Vec<usize> = Vec::new();
    let mut call_stack: Vec<Frame> = Vec::new();
    let mut sccs: Vec<Vec<usize>> = Vec::new();

    for start in 0..n {
        if indices[start].is_some() {
            continue;
        }
        indices[start] = Some(index_counter);
        lowlink[start] = index_counter;
        index_counter += 1;
        tarjan_stack.push(start);
        on_stack[start] = true;
        call_stack.push(Frame {
            node: start,
            neighbors: adj[start].iter().copied().collect(),
            next_edge: 0,
        });

        while let Some(frame) = call_stack.last_mut() {
            let v = frame.node;
            if frame.next_edge < frame.neighbors.len() {
                let w = frame.neighbors[frame.next_edge];
                frame.next_edge += 1;
                if indices[w].is_none() {
                    indices[w] = Some(index_counter);
                    lowlink[w] = index_counter;
                    index_counter += 1;
                    tarjan_stack.push(w);
                    on_stack[w] = true;
                    call_stack.push(Frame {
                        node: w,
                        neighbors: adj[w].iter().copied().collect(),
                        next_edge: 0,
                    });
                } else if on_stack[w] {
                    lowlink[v] = lowlink[v].min(indices[w].unwrap_or(usize::MAX));
                }
            } else {
                let finished = call_stack.pop().expect("non-empty frame");
                let v = finished.node;
                if let Some(parent) = call_stack.last() {
                    lowlink[parent.node] = lowlink[parent.node].min(lowlink[v]);
                }
                if Some(lowlink[v]) == indices[v] {
                    let mut comp = Vec::new();
                    while let Some(w) = tarjan_stack.pop() {
                        on_stack[w] = false;
                        comp.push(w);
                        if w == v {
                            break;
                        }
                    }
                    sccs.push(comp);
                }
            }
        }
    }

    sccs
}
