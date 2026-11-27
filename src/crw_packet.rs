//! Layer 2 LLM handoff emitter producing a compact, challengeable
//! Semantic Hotspot & Drift Packet for CRW Domain #1 and Family #11 reviews.

use crate::graph_topology::cap_topology_for_packet;
use crate::model::{
    CRW_PACKET_SCHEMA_VERSION, CrwHandoffPacket, FileRole, HotspotEntry, Snapshot, SnapshotDelta,
};
use crate::scoring::{to_hotspot_entry, top_hotspots};

pub fn build_crw_packet(
    snapshot: &Snapshot,
    drift: Option<SnapshotDelta>,
    top_k: usize,
) -> CrwHandoffPacket {
    let hotspots = top_hotspots(&snapshot.files, top_k);

    let mut dampened: Vec<HotspotEntry> = snapshot
        .files
        .iter()
        .filter(|f| f.role == FileRole::Production && f.dampening_factor < 1.0)
        .map(to_hotspot_entry)
        .collect();
    dampened.sort_by(|a, b| {
        b.prod_loc
            .cmp(&a.prod_loc)
            .then_with(|| a.path.cmp(&b.path))
    });
    dampened.truncate(top_k);

    let mut blanket_files: Vec<HotspotEntry> = snapshot
        .files
        .iter()
        .filter(|f| f.role == FileRole::Production && f.suppressions.blanket > 0)
        .map(to_hotspot_entry)
        .collect();
    blanket_files.sort_by(|a, b| {
        b.blanket_suppressions
            .cmp(&a.blanket_suppressions)
            .then_with(|| a.path.cmp(&b.path))
    });
    blanket_files.truncate(top_k);

    let co_change_clusters = snapshot
        .co_change_pairs
        .iter()
        .take(top_k)
        .cloned()
        .collect();

    let topology = cap_topology_for_packet(&snapshot.topology, top_k);

    let challenge_notes = vec![
        "Layer 1 static scores are challengeable signals, not automatic defect verdicts.".to_string(),
        "Verify whether each top hotspot interleaves orthogonal concerns or imposes an unnecessary working-set radius.".to_string(),
        "Audit dampened_counterexamples to confirm static tables and flat dispatchers do not conceal hidden multi-concern seams.".to_string(),
        "Inspect topology (sccs, bypasses, smeared_writes, top_nexus_nodes, phantom_couplings) under Domain #1 while preserving pure leaf value/error utilities and thin composition roots as counterevidence.".to_string(),
        "Inspect blanket_suppression_files for silent guardrail erosion under Family #11 (continuous-guardrail-and-gate-enforcement).".to_string(),
    ];

    CrwHandoffPacket {
        schema_version: CRW_PACKET_SCHEMA_VERSION,
        packet_kind: "semantic-hotspot-and-drift-packet".to_string(),
        target_families: vec![
            "organization-and-communication".to_string(),
            "continuing-processes-and-longitudinal-controls".to_string(),
        ],
        repo_label: snapshot.repo_label.clone(),
        commit: snapshot.commit.clone(),
        summary: snapshot.summary.clone(),
        profile: snapshot.profile.clone(),
        top_hotspots: hotspots,
        dampened_counterexamples: dampened,
        co_change_clusters,
        blanket_suppression_files: blanket_files,
        topology,
        drift,
        challenge_notes,
    }
}
