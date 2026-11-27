//! Explicit CLI parser and subcommand dispatch for `semantic-profiler`.

use crate::crw_packet::build_crw_packet;
use crate::delta::{compute_delta, evaluate_budgets};
use crate::ecosystem::model::EcosystemScanOptions;
use crate::ecosystem::scan_ecosystem;
use crate::graph_topology::{cap_topology_for_packet, export_graph_edges};
use crate::model::{
    CHECK_REPORT_SCHEMA_VERSION, CheckReport, JsonlRecord, SNAPSHOT_SCHEMA_VERSION,
    SemanticBudgets, Snapshot,
};
use crate::safe_io::{
    is_reparse_or_symlink, read_file_bounded, reject_reparse_or_symlink_ancestors,
};
use crate::scoring::top_hotspots;
use crate::{ScanOptions, scan_repository};
use std::fmt::Write as _;
use std::fs::{self, OpenOptions};
use std::io::Write;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};

pub const MAX_SNAPSHOT_BYTES: u64 = 64 * 1024 * 1024;
static NEXT_ATOMIC_TMP_ID: AtomicU64 = AtomicU64::new(0);

const USAGE: &str = "\
Usage:
  semantic-profiler check <repo-path> [--profile <path>] [--base <baseline.json>] [--window <N>] [--top <K>] [--json] [--output <path>] [--emit-crw-packet <path>] [--emit-graph-edges <path> | --graph-edges <path>] [--include-evals] [--require-profile]
  semantic-profiler scan <repo-path> [--window <N>] [--top <K>] [--profile <path>] [--output <path>] [--jsonl <path>] [--emit-crw-packet <path>] [--emit-graph-edges <path> | --graph-edges <path>] [--include-evals]
  semantic-profiler delta --base <base.json> --head <head.json> [--top <K>] [--output <path>] [--emit-crw-packet <path>] [--fail-on-budget]
  semantic-profiler ecosystem (--workspace-root <dir> | --roots <dir1> [<dir2> ...]) [--output <json_path>] [--impact <repo_name>] [--fail-on-cycle] [--scan-repos]

Subcommands:
  check      Scan a repository, evaluate semantic-profile.json budgets (and optional --base delta),
             print a human-readable or --json report, and exit 0 on pass, 2 on budget violation(s),
             or 1 on CLI/runtime error.
  scan       Analyze a repository and emit a portable JSON snapshot (plus optional JSONL,
             CRW handoff packet, and typed graph-edges export).
  delta      Compare two saved snapshots (--base and --head) for longitudinal drift and budgets.
  ecosystem  Scan a collection of repositories to build a cross-repo dependency, pin-skew,
             SCC cycle, and transitive blast-radius graph (exit 2 on cycle with --fail-on-cycle).
";

struct CheckArgs {
    repo: PathBuf,
    profile_path: Option<PathBuf>,
    base_path: Option<PathBuf>,
    window: usize,
    top_k: usize,
    json: bool,
    output_path: Option<PathBuf>,
    crw_packet_path: Option<PathBuf>,
    graph_edges_path: Option<PathBuf>,
    include_evals: bool,
    require_profile: bool,
}

struct ScanArgs {
    repo: PathBuf,
    window: usize,
    top_k: usize,
    profile_path: Option<PathBuf>,
    output_path: Option<PathBuf>,
    jsonl_path: Option<PathBuf>,
    crw_packet_path: Option<PathBuf>,
    graph_edges_path: Option<PathBuf>,
    include_evals: bool,
}

struct DeltaArgs {
    base_file: PathBuf,
    head_file: PathBuf,
    top_k: usize,
    output_path: Option<PathBuf>,
    crw_packet_path: Option<PathBuf>,
    fail_on_budget: bool,
}

struct EcosystemArgs {
    workspace_root: Option<PathBuf>,
    roots: Vec<PathBuf>,
    output_path: Option<PathBuf>,
    impact: Option<String>,
    fail_on_cycle: bool,
    scan_repos: bool,
}

pub fn run<I, S>(argv: I) -> Result<i32, String>
where
    I: IntoIterator<Item = S>,
    S: AsRef<str>,
{
    let args: Vec<String> = argv.into_iter().map(|s| s.as_ref().to_string()).collect();
    if args.len() < 2 {
        eprint!("{USAGE}");
        return Ok(2);
    }
    match args[1].as_str() {
        "-h" | "--help" => {
            print!("{USAGE}");
            Ok(0)
        }
        "check" => run_check(&args[2..]),
        "scan" => run_scan(&args[2..]),
        "delta" => run_delta(&args[2..]),
        "ecosystem" => run_ecosystem(&args[2..]),
        other => Err(format!("unknown subcommand '{other}'\n{USAGE}")),
    }
}

fn take_path_value(args: &[String], i: &mut usize, flag: &str) -> Result<PathBuf, String> {
    *i += 1;
    let raw = args
        .get(*i)
        .ok_or_else(|| format!("{flag} requires a path"))?;
    if raw.starts_with('-') && raw != "-" {
        return Err(format!(
            "{flag} requires a path, got option-like value '{raw}'"
        ));
    }
    *i += 1;
    Ok(PathBuf::from(raw))
}

fn take_usize_value(args: &[String], i: &mut usize, flag: &str) -> Result<usize, String> {
    *i += 1;
    let raw = args
        .get(*i)
        .ok_or_else(|| format!("{flag} requires a value"))?;
    let val = raw
        .parse::<usize>()
        .map_err(|_| format!("invalid {flag} integer: {raw}"))?;
    *i += 1;
    Ok(val)
}

fn set_once<T>(slot: &mut Option<T>, value: T, flag: &str) -> Result<(), String> {
    if slot.is_some() {
        return Err(format!("duplicate option: {flag}"));
    }
    *slot = Some(value);
    Ok(())
}

fn parse_check_args(args: &[String]) -> Result<Option<CheckArgs>, String> {
    let mut repo_path: Option<PathBuf> = None;
    let mut profile_path: Option<PathBuf> = None;
    let mut base_path: Option<PathBuf> = None;
    let mut window: Option<usize> = None;
    let mut top_k: Option<usize> = None;
    let mut json = false;
    let mut output_path: Option<PathBuf> = None;
    let mut crw_packet_path: Option<PathBuf> = None;
    let mut graph_edges_path: Option<PathBuf> = None;
    let mut include_evals = false;
    let mut require_profile = false;
    let mut after_double_dash = false;

    let mut i = 0usize;
    while i < args.len() {
        let arg = args[i].as_str();
        if !after_double_dash {
            match arg {
                "-h" | "--help" => {
                    print!("{USAGE}");
                    return Ok(None);
                }
                "--" => {
                    after_double_dash = true;
                    i += 1;
                    continue;
                }
                "--profile" => {
                    let v = take_path_value(args, &mut i, "--profile")?;
                    set_once(&mut profile_path, v, "--profile")?;
                    continue;
                }
                "--base" => {
                    let v = take_path_value(args, &mut i, "--base")?;
                    set_once(&mut base_path, v, "--base")?;
                    continue;
                }
                "--window" => {
                    let v = take_usize_value(args, &mut i, "--window")?;
                    set_once(&mut window, v, "--window")?;
                    continue;
                }
                "--top" => {
                    let v = take_usize_value(args, &mut i, "--top")?;
                    set_once(&mut top_k, v, "--top")?;
                    continue;
                }
                "--json" => {
                    json = true;
                    i += 1;
                    continue;
                }
                "--output" => {
                    let v = take_path_value(args, &mut i, "--output")?;
                    set_once(&mut output_path, v, "--output")?;
                    continue;
                }
                "--emit-crw-packet" => {
                    let v = take_path_value(args, &mut i, "--emit-crw-packet")?;
                    set_once(&mut crw_packet_path, v, "--emit-crw-packet")?;
                    continue;
                }
                "--emit-graph-edges" | "--graph-edges" => {
                    let v = take_path_value(args, &mut i, arg)?;
                    set_once(&mut graph_edges_path, v, arg)?;
                    continue;
                }
                "--include-evals" => {
                    include_evals = true;
                    i += 1;
                    continue;
                }
                "--require-profile" => {
                    require_profile = true;
                    i += 1;
                    continue;
                }
                flag if flag.starts_with('-') => {
                    return Err(format!("unknown option for check: {flag}\n{USAGE}"));
                }
                _ => {}
            }
        }

        if repo_path.is_some() {
            return Err(format!("unexpected positional argument: {arg}\n{USAGE}"));
        }
        repo_path = Some(PathBuf::from(arg));
        i += 1;
    }

    let repo = repo_path.ok_or_else(|| format!("missing <repo-path>\n{USAGE}"))?;
    Ok(Some(CheckArgs {
        repo,
        profile_path,
        base_path,
        window: window.unwrap_or(100),
        top_k: top_k.unwrap_or(15),
        json,
        output_path,
        crw_packet_path,
        graph_edges_path,
        include_evals,
        require_profile,
    }))
}

fn run_check(args: &[String]) -> Result<i32, String> {
    let Some(cfg) = parse_check_args(args)? else {
        return Ok(0);
    };

    // Fast pre-flight validation before walking files or invoking git.
    if !cfg.repo.is_dir() {
        return Err(format!(
            "scan target is not a directory: {}",
            cfg.repo.display()
        ));
    }
    if cfg.require_profile && cfg.profile_path.is_none() {
        let default_profile = cfg.repo.join("semantic-profile.json");
        if fs::symlink_metadata(&default_profile).is_err() {
            return Err(format!(
                "--require-profile was specified, but no semantic-profile.json was found in {}",
                cfg.repo.display()
            ));
        }
    }
    let base_snapshot = match &cfg.base_path {
        Some(base_file) => Some(read_snapshot(base_file)?),
        None => None,
    };

    let opts = ScanOptions {
        git_window: cfg.window,
        profile_path: cfg.profile_path,
        include_evals: cfg.include_evals,
    };
    let snapshot = scan_repository(&cfg.repo, &opts)?;

    if cfg.require_profile && snapshot.profile.loaded_from.is_none() {
        return Err(format!(
            "--require-profile was specified, but no semantic-profile.json was found in {}",
            cfg.repo.display()
        ));
    }

    let budgets_configured = snapshot
        .profile
        .budgets
        .as_ref()
        .is_some_and(SemanticBudgets::has_any);
    let mut warnings = Vec::new();
    if snapshot.profile.loaded_from.is_none() {
        warnings.push("no semantic-profile.json found; budget checks skipped".to_string());
    } else if !budgets_configured {
        warnings.push("loaded semantic profile defines no budgets; budget checks skipped".to_string());
    }

    let delta = base_snapshot
        .as_ref()
        .map(|base| compute_delta(base, &snapshot));

    let budget_violations = evaluate_budgets(&snapshot, snapshot.profile.budgets.as_ref());

    if let Some(ppath) = &cfg.crw_packet_path {
        let packet = build_crw_packet(&snapshot, delta.clone(), cfg.top_k);
        let text = serde_json::to_string_pretty(&packet)
            .map_err(|e| format!("failed to serialize CRW packet: {e}"))?;
        write_text(ppath, &(text + "\n"))?;
    }

    if let Some(epath) = &cfg.graph_edges_path {
        let export = export_graph_edges(&snapshot);
        let text = serde_json::to_string_pretty(&export)
            .map_err(|e| format!("failed to serialize graph edges: {e}"))?;
        write_text(epath, &(text + "\n"))?;
    }

    let passed = budget_violations.is_empty();
    let report = CheckReport {
        schema_version: CHECK_REPORT_SCHEMA_VERSION,
        passed,
        repo_label: snapshot.repo_label.clone(),
        commit: snapshot.commit.clone(),
        profile_loaded_from: snapshot.profile.loaded_from.clone(),
        budgets_configured,
        warnings,
        summary: snapshot.summary.clone(),
        budget_violations,
        top_hotspots: top_hotspots(&snapshot.files, cfg.top_k),
        topology: cap_topology_for_packet(&snapshot.topology, cfg.top_k),
        delta,
    };

    let rendered = if cfg.json {
        serde_json::to_string_pretty(&report)
            .map_err(|e| format!("failed to serialize check report: {e}"))?
            + "\n"
    } else {
        format_check_report(&report)
    };

    if let Some(opath) = &cfg.output_path {
        write_text(opath, &rendered)?;
    } else {
        print!("{rendered}");
    }

    Ok(if passed { 0 } else { 2 })
}

fn short_commit(commit: Option<&str>) -> String {
    commit
        .map(|c| c.chars().take(12).collect())
        .unwrap_or_else(|| "none".to_string())
}

fn format_check_report(report: &CheckReport) -> String {
    let mut out = String::new();
    let status = if report.passed { "PASS" } else { "FAIL" };
    let _ = writeln!(
        out,
        "semantic-profiler check: {status} ({} budget violation(s))",
        report.budget_violations.len()
    );

    let commit_label = short_commit(report.commit.as_deref());
    let _ = writeln!(
        out,
        "  repo: {} (commit: {commit_label})",
        report.repo_label
    );

    let profile_label = report.profile_loaded_from.as_deref().unwrap_or("none");
    let budgets_label = if report.budgets_configured {
        "active"
    } else {
        "none"
    };
    let _ = writeln!(
        out,
        "  profile: {profile_label} (budgets: {budgets_label})"
    );

    let s = &report.summary;
    let _ = writeln!(
        out,
        "  codebase: {} prod files, {} prod LOC, {} est tokens, top hotspot {:.2}",
        s.prod_files, s.prod_loc, s.est_prod_tokens, s.top_hotspot_score
    );
    let _ = writeln!(
        out,
        "  topology: sccs={} bypasses={} smeared_writes={} phantom_couplings={} blanket_suppressions={}",
        s.scc_count,
        s.bypass_count,
        s.smeared_write_count,
        s.phantom_coupling_count,
        s.blanket_suppressions
    );

    if let Some(d) = &report.delta {
        let base_label = short_commit(d.base_commit.as_deref());
        let _ = writeln!(
            out,
            "  delta vs base ({base_label}): prod_loc={:+} top_hotspot={:+.2} sccs={:+} bypasses={:+} smeared={:+} phantoms={:+}",
            d.prod_loc_delta,
            d.top_hotspot_score_delta,
            d.scc_count_delta,
            d.bypass_count_delta,
            d.smeared_write_count_delta,
            d.phantom_coupling_count_delta
        );
    }

    if !report.warnings.is_empty() {
        out.push_str("  warnings:\n");
        for w in &report.warnings {
            let _ = writeln!(out, "    - {w}");
        }
    }

    if !report.budget_violations.is_empty() {
        out.push_str("  budget violations:\n");
        for v in &report.budget_violations {
            let _ = writeln!(
                out,
                "    - {} on {}: {} > {}",
                v.rule, v.target, v.actual, v.limit
            );
        }
    }

    if !report.top_hotspots.is_empty() {
        out.push_str("  top hotspots:\n");
        for (idx, h) in report.top_hotspots.iter().take(5).enumerate() {
            let _ = writeln!(
                out,
                "    {}. {}  score={:.2}  loc={}  max_fn={}  fan_in={}  fan_out={}",
                idx + 1,
                h.path,
                h.hotspot_score,
                h.prod_loc,
                h.max_fn_loc,
                h.fan_in,
                h.fan_out
            );
        }
    }

    out
}

fn parse_scan_args(args: &[String]) -> Result<Option<ScanArgs>, String> {
    let mut repo_path: Option<PathBuf> = None;
    let mut window: Option<usize> = None;
    let mut top_k: Option<usize> = None;
    let mut profile_path: Option<PathBuf> = None;
    let mut output_path: Option<PathBuf> = None;
    let mut jsonl_path: Option<PathBuf> = None;
    let mut crw_packet_path: Option<PathBuf> = None;
    let mut graph_edges_path: Option<PathBuf> = None;
    let mut include_evals = false;
    let mut after_double_dash = false;

    let mut i = 0usize;
    while i < args.len() {
        let arg = args[i].as_str();
        if !after_double_dash {
            match arg {
                "-h" | "--help" => {
                    print!("{USAGE}");
                    return Ok(None);
                }
                "--" => {
                    after_double_dash = true;
                    i += 1;
                    continue;
                }
                "--window" => {
                    let v = take_usize_value(args, &mut i, "--window")?;
                    set_once(&mut window, v, "--window")?;
                    continue;
                }
                "--top" => {
                    let v = take_usize_value(args, &mut i, "--top")?;
                    set_once(&mut top_k, v, "--top")?;
                    continue;
                }
                "--profile" => {
                    let v = take_path_value(args, &mut i, "--profile")?;
                    set_once(&mut profile_path, v, "--profile")?;
                    continue;
                }
                "--output" => {
                    let v = take_path_value(args, &mut i, "--output")?;
                    set_once(&mut output_path, v, "--output")?;
                    continue;
                }
                "--jsonl" => {
                    let v = take_path_value(args, &mut i, "--jsonl")?;
                    set_once(&mut jsonl_path, v, "--jsonl")?;
                    continue;
                }
                "--emit-crw-packet" => {
                    let v = take_path_value(args, &mut i, "--emit-crw-packet")?;
                    set_once(&mut crw_packet_path, v, "--emit-crw-packet")?;
                    continue;
                }
                "--emit-graph-edges" | "--graph-edges" => {
                    let v = take_path_value(args, &mut i, arg)?;
                    set_once(&mut graph_edges_path, v, arg)?;
                    continue;
                }
                "--include-evals" => {
                    include_evals = true;
                    i += 1;
                    continue;
                }
                flag if flag.starts_with('-') => {
                    return Err(format!("unknown option for scan: {flag}\n{USAGE}"));
                }
                _ => {}
            }
        }

        if repo_path.is_some() {
            return Err(format!("unexpected positional argument: {arg}\n{USAGE}"));
        }
        repo_path = Some(PathBuf::from(arg));
        i += 1;
    }

    let repo = repo_path.ok_or_else(|| format!("missing <repo-path>\n{USAGE}"))?;
    Ok(Some(ScanArgs {
        repo,
        window: window.unwrap_or(100),
        top_k: top_k.unwrap_or(15),
        profile_path,
        output_path,
        jsonl_path,
        crw_packet_path,
        graph_edges_path,
        include_evals,
    }))
}

fn run_scan(args: &[String]) -> Result<i32, String> {
    let Some(cfg) = parse_scan_args(args)? else {
        return Ok(0);
    };

    let opts = ScanOptions {
        git_window: cfg.window,
        profile_path: cfg.profile_path,
        include_evals: cfg.include_evals,
    };
    let snapshot = scan_repository(&cfg.repo, &opts)?;

    if let Some(jpath) = &cfg.jsonl_path {
        let record = JsonlRecord {
            schema_version: SNAPSHOT_SCHEMA_VERSION,
            repo_label: snapshot.repo_label.clone(),
            commit: snapshot.commit.clone(),
            summary: snapshot.summary.clone(),
            top_hotspots: top_hotspots(&snapshot.files, cfg.top_k),
            top_co_change_pairs: snapshot
                .co_change_pairs
                .iter()
                .take(cfg.top_k)
                .cloned()
                .collect(),
        };
        let line = serde_json::to_string(&record)
            .map_err(|e| format!("failed to serialize jsonl record: {e}"))?;
        append_line(jpath, &line)?;
    }

    if let Some(ppath) = &cfg.crw_packet_path {
        let packet = build_crw_packet(&snapshot, None, cfg.top_k);
        let text = serde_json::to_string_pretty(&packet)
            .map_err(|e| format!("failed to serialize CRW packet: {e}"))?;
        write_text(ppath, &(text + "\n"))?;
    }

    if let Some(epath) = &cfg.graph_edges_path {
        let export = export_graph_edges(&snapshot);
        let text = serde_json::to_string_pretty(&export)
            .map_err(|e| format!("failed to serialize graph edges: {e}"))?;
        write_text(epath, &(text + "\n"))?;
    }

    let rendered = serde_json::to_string_pretty(&snapshot)
        .map_err(|e| format!("failed to serialize snapshot: {e}"))?;
    if let Some(opath) = &cfg.output_path {
        write_text(opath, &(rendered + "\n"))?;
    } else {
        println!("{rendered}");
    }
    Ok(0)
}

fn parse_delta_args(args: &[String]) -> Result<Option<DeltaArgs>, String> {
    let mut base_path: Option<PathBuf> = None;
    let mut head_path: Option<PathBuf> = None;
    let mut top_k: Option<usize> = None;
    let mut output_path: Option<PathBuf> = None;
    let mut crw_packet_path: Option<PathBuf> = None;
    let mut fail_on_budget = false;

    let mut i = 0usize;
    while i < args.len() {
        match args[i].as_str() {
            "-h" | "--help" => {
                print!("{USAGE}");
                return Ok(None);
            }
            "--base" => {
                let v = take_path_value(args, &mut i, "--base")?;
                set_once(&mut base_path, v, "--base")?;
            }
            "--head" => {
                let v = take_path_value(args, &mut i, "--head")?;
                set_once(&mut head_path, v, "--head")?;
            }
            "--top" => {
                let v = take_usize_value(args, &mut i, "--top")?;
                set_once(&mut top_k, v, "--top")?;
            }
            "--output" => {
                let v = take_path_value(args, &mut i, "--output")?;
                set_once(&mut output_path, v, "--output")?;
            }
            "--emit-crw-packet" => {
                let v = take_path_value(args, &mut i, "--emit-crw-packet")?;
                set_once(&mut crw_packet_path, v, "--emit-crw-packet")?;
            }
            "--fail-on-budget" => {
                fail_on_budget = true;
                i += 1;
            }
            other => {
                return Err(format!("unknown option for delta: {other}\n{USAGE}"));
            }
        }
    }

    let base_file = base_path.ok_or_else(|| format!("missing --base\n{USAGE}"))?;
    let head_file = head_path.ok_or_else(|| format!("missing --head\n{USAGE}"))?;
    Ok(Some(DeltaArgs {
        base_file,
        head_file,
        top_k: top_k.unwrap_or(15),
        output_path,
        crw_packet_path,
        fail_on_budget,
    }))
}

fn run_delta(args: &[String]) -> Result<i32, String> {
    let Some(cfg) = parse_delta_args(args)? else {
        return Ok(0);
    };

    let base: Snapshot = read_snapshot(&cfg.base_file)?;
    let head: Snapshot = read_snapshot(&cfg.head_file)?;
    let delta = compute_delta(&base, &head);

    if let Some(ppath) = &cfg.crw_packet_path {
        let packet = build_crw_packet(&head, Some(delta.clone()), cfg.top_k);
        let text = serde_json::to_string_pretty(&packet)
            .map_err(|e| format!("failed to serialize CRW packet: {e}"))?;
        write_text(ppath, &(text + "\n"))?;
    }

    let rendered = serde_json::to_string_pretty(&delta)
        .map_err(|e| format!("failed to serialize delta: {e}"))?;
    if let Some(opath) = &cfg.output_path {
        write_text(opath, &(rendered + "\n"))?;
    } else {
        println!("{rendered}");
    }

    if cfg.fail_on_budget && !delta.budget_violations.is_empty() {
        eprintln!(
            "semantic budget failed ({} violation(s)):",
            delta.budget_violations.len()
        );
        for v in &delta.budget_violations {
            eprintln!("  - {} on {}: {} > {}", v.rule, v.target, v.actual, v.limit);
        }
        return Ok(2);
    }
    Ok(0)
}

fn take_string_value(args: &[String], i: &mut usize, flag: &str) -> Result<String, String> {
    *i += 1;
    let raw = args
        .get(*i)
        .ok_or_else(|| format!("{flag} requires a value"))?;
    if raw.starts_with('-') {
        return Err(format!(
            "{flag} requires a value, got option-like token '{raw}'"
        ));
    }
    *i += 1;
    Ok(raw.clone())
}

fn parse_ecosystem_args(args: &[String]) -> Result<Option<EcosystemArgs>, String> {
    let mut workspace_root: Option<PathBuf> = None;
    let mut roots: Vec<PathBuf> = Vec::new();
    let mut output_path: Option<PathBuf> = None;
    let mut impact: Option<String> = None;
    let mut fail_on_cycle = false;
    let mut scan_repos = false;

    let mut i = 0usize;
    while i < args.len() {
        match args[i].as_str() {
            "-h" | "--help" => {
                print!("{USAGE}");
                return Ok(None);
            }
            "--workspace-root" => {
                let v = take_path_value(args, &mut i, "--workspace-root")?;
                set_once(&mut workspace_root, v, "--workspace-root")?;
            }
            "--roots" => {
                i += 1;
                let start = i;
                while let Some(tok) = args.get(i) {
                    if tok.starts_with('-') {
                        break;
                    }
                    roots.push(PathBuf::from(tok));
                    i += 1;
                }
                if i == start {
                    return Err(format!("--roots requires at least one directory\n{USAGE}"));
                }
            }
            "--output" => {
                let v = take_path_value(args, &mut i, "--output")?;
                set_once(&mut output_path, v, "--output")?;
            }
            "--impact" => {
                let v = take_string_value(args, &mut i, "--impact")?;
                set_once(&mut impact, v, "--impact")?;
            }
            "--fail-on-cycle" => {
                fail_on_cycle = true;
                i += 1;
            }
            "--scan-repos" => {
                scan_repos = true;
                i += 1;
            }
            other => {
                return Err(format!("unknown option for ecosystem: {other}\n{USAGE}"));
            }
        }
    }

    if workspace_root.is_none() && roots.is_empty() {
        return Err(format!(
            "ecosystem requires --workspace-root <dir> and/or --roots <dir>...\n{USAGE}"
        ));
    }

    Ok(Some(EcosystemArgs {
        workspace_root,
        roots,
        output_path,
        impact,
        fail_on_cycle,
        scan_repos,
    }))
}

fn run_ecosystem(args: &[String]) -> Result<i32, String> {
    let Some(cfg) = parse_ecosystem_args(args)? else {
        return Ok(0);
    };

    let options = EcosystemScanOptions {
        workspace_root: cfg.workspace_root,
        roots: cfg.roots,
        scan_repos: cfg.scan_repos,
        impact_target: cfg.impact,
    };
    let graph = scan_ecosystem(&options)?;
    let rendered = serde_json::to_string_pretty(&graph)
        .map_err(|e| format!("failed to serialize ecosystem graph: {e}"))?;

    if let Some(opath) = &cfg.output_path {
        write_text(opath, &(rendered + "\n"))?;
    } else {
        println!("{rendered}");
    }

    if cfg.fail_on_cycle && !graph.sccs.is_empty() {
        eprintln!(
            "ecosystem cycle check failed ({} repo-level SCC(s)):",
            graph.sccs.len()
        );
        for scc in &graph.sccs {
            eprintln!("  - {}: {}", scc.id, scc.repos.join(" <-> "));
        }
        return Ok(2);
    }
    Ok(0)
}

fn read_snapshot(path: &Path) -> Result<Snapshot, String> {
    let sym_meta = fs::symlink_metadata(path)
        .map_err(|e| format!("failed to stat snapshot {}: {e}", path.display()))?;
    if is_reparse_or_symlink(&sym_meta) {
        return Err(format!(
            "refusing symlink or reparse point snapshot: {}",
            path.display()
        ));
    }
    let bytes = read_file_bounded(path, MAX_SNAPSHOT_BYTES)
        .map_err(|e| format!("failed to read snapshot {}: {e}", path.display()))?;
    let raw = String::from_utf8(bytes)
        .map_err(|e| format!("snapshot {} is not valid UTF-8: {e}", path.display()))?;
    let clean = raw.strip_prefix('\u{feff}').unwrap_or(&raw);
    serde_json::from_str(clean)
        .map_err(|e| format!("invalid snapshot JSON {}: {e}", path.display()))
}

fn ensure_safe_output_path(path: &Path) -> Result<PathBuf, String> {
    let cleaned = reject_reparse_or_symlink_ancestors(path, "output")?;
    match fs::symlink_metadata(&cleaned) {
        Ok(meta) => {
            if is_reparse_or_symlink(&meta) {
                return Err(format!(
                    "refusing to write to symlink or reparse point: {}",
                    cleaned.display()
                ));
            }
            if !meta.is_file() {
                return Err(format!(
                    "refusing to write to non-regular file: {}",
                    cleaned.display()
                ));
            }
            Ok(cleaned)
        }
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(cleaned),
        Err(e) => Err(format!("failed to stat output {}: {e}", cleaned.display())),
    }
}

fn write_text(path: &Path, text: &str) -> Result<(), String> {
    let cleaned = ensure_safe_output_path(path)?;
    let parent = match cleaned.parent() {
        Some(p) if !p.as_os_str().is_empty() => {
            fs::create_dir_all(p)
                .map_err(|e| format!("failed to create directory {}: {e}", p.display()))?;
            p
        }
        _ => Path::new("."),
    };
    let file_name = cleaned
        .file_name()
        .and_then(|s| s.to_str())
        .unwrap_or("output");
    let seq = NEXT_ATOMIC_TMP_ID.fetch_add(1, Ordering::Relaxed);
    let tmp_path = parent.join(format!(
        ".{file_name}.tmp.{}.{seq}",
        std::process::id()
    ));
    let mut handle = OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&tmp_path)
        .map_err(|e| format!("failed to create temp file {}: {e}", tmp_path.display()))?;
    if let Err(e) = handle.write_all(text.as_bytes()).and_then(|()| handle.sync_all()) {
        drop(handle);
        let _ = fs::remove_file(&tmp_path);
        return Err(format!("failed to write {}: {e}", cleaned.display()));
    }
    drop(handle);
    if let Err(e) = fs::rename(&tmp_path, &cleaned) {
        let _ = fs::remove_file(&tmp_path);
        return Err(format!("failed to finalize {}: {e}", cleaned.display()));
    }
    Ok(())
}

fn append_line(path: &Path, line: &str) -> Result<(), String> {
    let cleaned = ensure_safe_output_path(path)?;
    if let Some(parent) = cleaned.parent()
        && !parent.as_os_str().is_empty()
    {
        fs::create_dir_all(parent)
            .map_err(|e| format!("failed to create directory {}: {e}", parent.display()))?;
    }
    let mut handle = OpenOptions::new()
        .create(true)
        .append(true)
        .open(&cleaned)
        .map_err(|e| format!("failed to open jsonl {}: {e}", cleaned.display()))?;
    writeln!(handle, "{line}").map_err(|e| format!("failed to append jsonl: {e}"))
}
