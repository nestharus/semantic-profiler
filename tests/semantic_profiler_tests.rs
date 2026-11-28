//! Unit and end-to-end integration tests for `semantic-profiler`.

use semantic_profiler::cli;
use semantic_profiler::crw_packet::build_crw_packet;
use semantic_profiler::delta::{compute_delta, evaluate_budgets};
use semantic_profiler::discovery::{discover_files_with_limit, read_file_bounded};
use semantic_profiler::graph_topology::export_graph_edges;
use semantic_profiler::model::{
    CheckReport, CrwHandoffPacket, FileClassification, FileRole, GraphEdgesExport, Language,
    SemanticBudgets, Snapshot,
};
use semantic_profiler::profile_config::{RepoProfile, glob_match};
use semantic_profiler::scoring::round2;
use semantic_profiler::{ScanOptions, scan_repository};
use std::fs;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::sync::atomic::{AtomicUsize, Ordering};

#[cfg(windows)]
use std::os::windows::process::CommandExt;

#[cfg(windows)]
const CREATE_NO_WINDOW: u32 = 0x0800_0000;

static NEXT_TMP: AtomicUsize = AtomicUsize::new(0);

struct TempDir(PathBuf);

impl TempDir {
    fn new(name: &str) -> Self {
        let dir = std::env::temp_dir().join(format!(
            "semantic-profiler-test-{}-{}-{}",
            name,
            std::process::id(),
            NEXT_TMP.fetch_add(1, Ordering::Relaxed)
        ));
        fs::create_dir_all(&dir).unwrap();
        Self(dir)
    }

    fn path(&self) -> &Path {
        &self.0
    }
}

impl Drop for TempDir {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

fn manifest_dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
}

fn run_git(dir: &Path, args: &[&str]) {
    let mut cmd = Command::new("git");
    cmd.arg("-C")
        .arg(dir)
        .args(args)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    #[cfg(windows)]
    cmd.creation_flags(CREATE_NO_WINDOW);
    let out = cmd.output().expect("spawn git");
    assert!(
        out.status.success(),
        "git {:?} failed: {}",
        args,
        String::from_utf8_lossy(&out.stderr)
    );
}

#[test]
fn glob_matcher_handles_wildcards_and_double_star() {
    assert!(glob_match("src/char_table.rs", "src/char_table.rs"));
    assert!(glob_match("tests/**", "tests/unit/router.rs"));
    assert!(glob_match("**/*_test.rs", "crates/core/src/a_test.rs"));
    assert!(!glob_match("src/*.rs", "src/sub/mod.rs"));
    assert!(glob_match("src/**/mod.rs", "src/a/b/mod.rs"));
}

#[test]
fn distinguishes_monolithic_dispatcher_from_static_table_and_flat_router() {
    let tmp = TempDir::new("monolith-vs-dampened");
    let mono = tmp.path().join("monolith");
    let clean = tmp.path().join("dampened");
    fs::create_dir_all(mono.join("src")).unwrap();
    fs::create_dir_all(clean.join("src")).unwrap();

    // Monolithic deeply nested 9-parameter dispatcher with 2 suppressions.
    let mut mono_src = String::from(
        "#[allow(clippy::too_many_arguments)]\n#[allow(clippy::cognitive_complexity)]\npub fn dispatch(a: i32, b: i32, c: i32, d: i32, e: i32, f: i32, g: i32, h: i32, i: i32) -> i32 {\n",
    );
    mono_src.push_str(
        "    if a > 0 {\n        if b > 0 {\n            if c > 0 {\n                if d > 0 {\n                    if e > 0 {\n                        if f > 0 {\n                            if g > 0 {\n                                return h + i;\n                            }\n                        }\n                    }\n                }\n            }\n        }\n    }\n",
    );
    for idx in 0..220 {
        mono_src.push_str(&format!("    let _v{idx} = a + {idx};\n"));
    }
    mono_src.push_str("    0\n}\n");
    fs::write(mono.join("src/dispatcher.rs"), mono_src).unwrap();

    // Clean counterexample: 3,200-LOC static data table + shallow exhaustive flat dispatcher.
    fs::write(
        clean.join("semantic-profile.json"),
        r#"{
  "schema_version": 1,
  "cohesive_data_globs": ["src/char_table.rs"],
  "flat_dispatcher_globs": ["src/opcode_dispatch.rs"]
}
"#,
    )
    .unwrap();
    let mut table_src = String::from("pub const CHAR_TABLE: &[u16] = &[\n");
    for idx in 0..3200 {
        table_src.push_str(&format!("    {idx},\n"));
    }
    table_src.push_str("];\n");
    fs::write(clean.join("src/char_table.rs"), table_src).unwrap();

    let mut flat_src = String::from("pub fn route(op: u8) -> &'static str {\n    match op {\n");
    for op in 0..40u8 {
        flat_src.push_str(&format!("        {op} => \"op_{op}\",\n"));
    }
    flat_src.push_str("        _ => \"unknown\",\n    }\n}\n");
    fs::write(clean.join("src/opcode_dispatch.rs"), flat_src).unwrap();

    let opts = ScanOptions {
        git_window: 0,
        profile_path: None,
        include_evals: false,
    };
    let snap_mono = scan_repository(&mono, &opts).expect("scan monolith");
    let snap_clean = scan_repository(&clean, &opts).expect("scan dampened");

    let disp = snap_mono
        .files
        .iter()
        .find(|f| f.path == "src/dispatcher.rs")
        .expect("src/dispatcher.rs");
    assert_eq!(disp.role, FileRole::Production);
    assert_eq!(disp.classification, FileClassification::Standard);
    assert!(disp.max_nesting_depth >= 7);
    assert_eq!(disp.max_param_count, 9);
    assert_eq!(disp.suppressions.total, 2);
    assert_eq!(disp.dampening_factor, 1.0);

    let table = snap_clean
        .files
        .iter()
        .find(|f| f.path == "src/char_table.rs")
        .expect("src/char_table.rs");
    assert!(table.prod_loc >= 3200);
    assert_eq!(table.classification, FileClassification::StaticDataTable);
    assert!(table.dampening_factor < 0.1);

    let router = snap_clean
        .files
        .iter()
        .find(|f| f.path == "src/opcode_dispatch.rs")
        .expect("src/opcode_dispatch.rs");
    assert_eq!(router.classification, FileClassification::FlatDispatcher);
    assert!(router.dampening_factor <= 0.25);
    assert_eq!(
        snap_clean.profile.loaded_from.as_deref(),
        Some("semantic-profile.json")
    );

    assert!(
        disp.hotspot_score > table.hotspot_score * 3.0,
        "expected monolithic dispatcher ({}) >> static table ({})",
        disp.hotspot_score,
        table.hotspot_score
    );
    assert!(
        disp.hotspot_score > router.hotspot_score * 5.0,
        "expected monolithic dispatcher ({}) >> flat dispatcher ({})",
        disp.hotspot_score,
        router.hotspot_score
    );

    let packet = build_crw_packet(&snap_clean, None, 10);
    assert!(
        packet
            .dampened_counterexamples
            .iter()
            .any(|e| e.path == "src/char_table.rs")
    );
    assert!(
        packet
            .dampened_counterexamples
            .iter()
            .any(|e| e.path == "src/opcode_dispatch.rs")
    );
}

#[test]
fn separates_blanket_suppressions_from_justified_narrow_ffi_allow() {
    let tmp = TempDir::new("suppressions-calibration");
    let bad = tmp.path().join("blanket");
    let good = tmp.path().join("justified");
    fs::create_dir_all(bad.join("src")).unwrap();
    fs::create_dir_all(good.join("src/ffi")).unwrap();

    fs::write(
        bad.join("src/eroded.rs"),
        concat!(
            "#![allow(warnings)]\n",
            "#![allow(clippy::all)]\n",
            "#[allow(clippy::pedantic)]\n",
            "pub fn f() -> u32 { 1 }\n",
        ),
    )
    .unwrap();
    fs::write(
        good.join("src/ffi/native_codec.rs"),
        concat!(
            "// FFI C-ABI layout requires snake_case symbol names matching upstream headers.\n",
            "#[allow(non_camel_case_types)]\n",
            "pub struct c_frame_header { pub len: u32 }\n",
        ),
    )
    .unwrap();

    let opts = ScanOptions {
        git_window: 0,
        ..Default::default()
    };
    let snap_bad = scan_repository(&bad, &opts).expect("scan blanket");
    let snap_good = scan_repository(&good, &opts).expect("scan justified");

    assert_eq!(snap_bad.summary.blanket_suppressions, 3);
    assert_eq!(snap_good.summary.blanket_suppressions, 0);
    let ffi = snap_good
        .files
        .iter()
        .find(|f| f.path == "src/ffi/native_codec.rs")
        .expect("ffi file");
    assert_eq!(ffi.suppressions.blanket, 0);
    assert_eq!(ffi.suppressions.narrow, 1);
    assert_eq!(ffi.suppressions.justified_narrow, 1);
}

#[test]
fn rust_inline_cfg_test_separated_from_production_loc() {
    let tmp = TempDir::new("inline-cfg-test");
    let src_dir = tmp.path().join("src");
    fs::create_dir_all(&src_dir).unwrap();

    let mut code = String::from(
        "pub fn add(a: i32, b: i32) -> i32 {\n    a + b\n}\n\n#[cfg(test)]\nmod tests {\n    use super::*;\n",
    );
    for i in 0..30 {
        code.push_str(&format!(
            "    #[test]\n    fn case_{i}() {{\n        assert_eq!(add({i}, 1), {});\n    }}\n",
            i + 1
        ));
    }
    code.push_str("}\n");
    fs::write(src_dir.join("lib.rs"), code).unwrap();

    let snap = scan_repository(
        tmp.path(),
        &ScanOptions {
            git_window: 0,
            ..Default::default()
        },
    )
    .expect("scan");
    let lib = snap.files.iter().find(|f| f.path == "src/lib.rs").unwrap();
    assert!(lib.prod_loc <= 6, "prod_loc was {}", lib.prod_loc);
    assert!(
        lib.inline_test_loc >= 120,
        "inline_test_loc was {}",
        lib.inline_test_loc
    );
    assert_eq!(lib.function_count, 1);
    assert_eq!(lib.max_fn_name.as_deref(), Some("add"));
}

#[test]
fn git_churn_co_change_delta_crw_packet_and_budget_gate() {
    let tmp = TempDir::new("git-delta");
    let repo = tmp.path().join("repo");
    fs::create_dir_all(repo.join("src")).unwrap();

    run_git(&repo, &["init", "-b", "main"]);
    run_git(&repo, &["config", "user.email", "test@example.com"]);
    run_git(&repo, &["config", "user.name", "Test User"]);

    fs::write(
        repo.join("semantic-profile.json"),
        r#"{
  "schema_version": 1,
  "domain_vocabulary": ["dispatch", "ledger"],
  "budgets": {
    "max_blanket_suppressions": 0
  }
}
"#,
    )
    .unwrap();
    fs::write(
        repo.join("src/state.rs"),
        "pub struct State { pub count: u32 }\n",
    )
    .unwrap();
    fs::write(
        repo.join("src/dispatcher.rs"),
        "use crate::state::State;\npub fn step(s: &mut State) { s.count += 1; }\n",
    )
    .unwrap();
    run_git(&repo, &["add", "."]);
    run_git(&repo, &["commit", "-m", "initial"]);

    let base_json = tmp.path().join("base.json");
    let jsonl_path = tmp.path().join("history.jsonl");
    let exit_scan_1 = cli::run([
        "semantic-profiler",
        "scan",
        repo.to_str().unwrap(),
        "--window",
        "20",
        "--output",
        base_json.to_str().unwrap(),
        "--jsonl",
        jsonl_path.to_str().unwrap(),
    ])
    .expect("base scan");
    assert_eq!(exit_scan_1, 0);

    for rev in 1..=3 {
        fs::write(
            repo.join("src/state.rs"),
            format!(
                "pub struct State {{ pub count: u32, pub rev: u32 }}\npub const REV: u32 = {rev};\n"
            ),
        )
        .unwrap();
        let blanket = if rev == 3 {
            "#![allow(clippy::all)]\n"
        } else {
            ""
        };
        fs::write(
            repo.join("src/dispatcher.rs"),
            format!(
                "{blanket}use crate::state::State;\npub fn step(s: &mut State, a: i32, b: i32, c: i32, d: i32, e: i32, f: i32) {{\n    if a > 0 {{\n        if b > 0 {{\n            if c > 0 {{\n                if d > 0 {{\n                    if e > 0 {{\n                        if f > 0 {{\n                            s.count += {rev};\n                        }}\n                    }}\n                }}\n            }}\n        }}\n    }}\n}}\n"
            ),
        )
        .unwrap();
        run_git(&repo, &["add", "."]);
        run_git(&repo, &["commit", "-m", &format!("cochange {rev}")]);
    }

    let head_json = tmp.path().join("head.json");
    let exit_scan_2 = cli::run([
        "semantic-profiler",
        "scan",
        repo.to_str().unwrap(),
        "--window",
        "20",
        "--output",
        head_json.to_str().unwrap(),
        "--jsonl",
        jsonl_path.to_str().unwrap(),
    ])
    .expect("head scan");
    assert_eq!(exit_scan_2, 0);

    let head_snap: Snapshot =
        serde_json::from_str(&fs::read_to_string(&head_json).unwrap()).unwrap();
    assert!(head_snap.git_available);
    assert_eq!(head_snap.git_commits_scanned, 4);
    let pair = head_snap
        .co_change_pairs
        .iter()
        .find(|p| p.file_a == "src/dispatcher.rs" && p.file_b == "src/state.rs")
        .expect("co-change pair");
    assert_eq!(pair.co_changes, 4);

    let delta_json = tmp.path().join("delta.json");
    let packet_json = tmp.path().join("packet.json");
    let delta_exit = cli::run([
        "semantic-profiler",
        "delta",
        "--base",
        base_json.to_str().unwrap(),
        "--head",
        head_json.to_str().unwrap(),
        "--output",
        delta_json.to_str().unwrap(),
        "--emit-crw-packet",
        packet_json.to_str().unwrap(),
        "--fail-on-budget",
    ])
    .expect("delta run");
    assert_eq!(delta_exit, 2, "budget violation should exit 2");

    let base_snap: Snapshot =
        serde_json::from_str(&fs::read_to_string(&base_json).unwrap()).unwrap();
    let delta = compute_delta(&base_snap, &head_snap);
    assert!(!delta.rising_hotspots.is_empty());
    assert_eq!(delta.rising_hotspots[0].path, "src/dispatcher.rs");
    assert_eq!(delta.blanket_suppressions_delta, 1);
    assert!(!delta.budget_violations.is_empty());

    let packet: CrwHandoffPacket =
        serde_json::from_str(&fs::read_to_string(&packet_json).unwrap()).unwrap();
    assert_eq!(packet.packet_kind, "semantic-hotspot-and-drift-packet");
    assert!(packet.drift.is_some());
    assert!(
        packet
            .blanket_suppression_files
            .iter()
            .any(|f| f.path == "src/dispatcher.rs")
    );

    let jsonl_lines: Vec<String> = fs::read_to_string(&jsonl_path)
        .unwrap()
        .lines()
        .map(String::from)
        .collect();
    assert_eq!(jsonl_lines.len(), 2);
}

#[test]
fn multi_language_analysis_and_graceful_fallback_on_corrupt_inputs() {
    let tmp = TempDir::new("multi-lang");
    fs::create_dir_all(tmp.path().join("pkg")).unwrap();
    fs::create_dir_all(tmp.path().join("tests")).unwrap();

    fs::write(
        tmp.path().join("pkg/worker.py"),
        "from .helper import run\n\ndef process(a, b, c, d, e, f):\n    if a:\n        for x in b:\n            if x:\n                if c:\n                    return run(x)  # noqa\n    return None  # noqa: E501\n",
    )
    .unwrap();
    fs::write(
        tmp.path().join("pkg/helper.py"),
        "def run(x):\n    return x\n",
    )
    .unwrap();
    fs::write(
        tmp.path().join("tests/test_worker.py"),
        "def test_ok():\n    assert True\n",
    )
    .unwrap();
    fs::write(
        tmp.path().join("pkg/broken.rs"),
        "pub fn broken( { {{{{ not valid rust\n",
    )
    .unwrap();
    fs::write(tmp.path().join("pkg/binary.py"), [0xff, 0xfe, 0x00, 0x80]).unwrap();

    let snap = scan_repository(
        tmp.path(),
        &ScanOptions {
            git_window: 0,
            ..Default::default()
        },
    )
    .expect("scan multi-lang");

    let py = snap
        .files
        .iter()
        .find(|f| f.path == "pkg/worker.py")
        .expect("worker.py");
    assert_eq!(py.language, Language::Python);
    assert_eq!(py.max_param_count, 6);
    assert_eq!(py.max_nesting_depth, 4);
    assert_eq!(py.suppressions.blanket, 1);
    assert_eq!(py.suppressions.narrow, 1);
    assert_eq!(py.fan_out, 1);

    let test_py = snap
        .files
        .iter()
        .find(|f| f.path == "tests/test_worker.py")
        .expect("test_worker.py");
    assert_eq!(test_py.role, FileRole::Test);
    assert_eq!(test_py.hotspot_score, 0.0);

    let broken = snap
        .files
        .iter()
        .find(|f| f.path == "pkg/broken.rs")
        .expect("broken.rs");
    assert!(broken.parse_fallback);

    assert!(
        snap.skipped_files
            .iter()
            .any(|s| s.path == "pkg/binary.py" && s.reason.contains("non-UTF-8"))
    );
}

#[test]
fn subcommand_help_returns_zero_and_double_dash_allows_leading_dash_path() {
    let exe = env!("CARGO_BIN_EXE_semantic-profiler");
    for args in [
        vec!["--help"],
        vec!["-h"],
        vec!["check", "--help"],
        vec!["check", "-h"],
        vec!["scan", "--help"],
        vec!["scan", "-h"],
        vec!["delta", "--help"],
        vec!["delta", "-h"],
    ] {
        let mut cmd = Command::new(exe);
        cmd.args(&args)
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped());
        #[cfg(windows)]
        cmd.creation_flags(CREATE_NO_WINDOW);
        let out = cmd.output().expect("spawn help");
        assert!(out.status.success(), "{args:?} should exit 0");
        let stdout = String::from_utf8_lossy(&out.stdout);
        assert!(
            stdout.contains("Usage:")
                && stdout.contains("semantic-profiler check")
                && stdout.contains("semantic-profiler scan")
                && stdout.contains("semantic-profiler delta"),
            "{args:?} should print full usage to stdout, got: {stdout}"
        );
        assert!(out.stderr.is_empty(), "{args:?} should not write to stderr");
    }

    let mut zero_cmd = Command::new(exe);
    zero_cmd
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    #[cfg(windows)]
    zero_cmd.creation_flags(CREATE_NO_WINDOW);
    let zero_out = zero_cmd.output().expect("spawn zero args");
    assert_eq!(zero_out.status.code(), Some(2));
    let zero_err = String::from_utf8_lossy(&zero_out.stderr);
    assert!(zero_err.starts_with("Usage:"), "got: {zero_err}");

    let tmp = TempDir::new("double-dash");
    let dash_dir = tmp.path().join("-dash-repo");
    fs::create_dir_all(dash_dir.join("src")).unwrap();
    fs::write(dash_dir.join("src/lib.rs"), "pub fn ok() -> u32 { 1 }\n").unwrap();
    let out_json = tmp.path().join("out.json");

    let mut dash_cmd = Command::new(exe);
    dash_cmd
        .current_dir(tmp.path())
        .args([
            "scan",
            "--window",
            "0",
            "--output",
            out_json.to_str().unwrap(),
            "--",
            "-dash-repo",
        ])
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    #[cfg(windows)]
    dash_cmd.creation_flags(CREATE_NO_WINDOW);
    let dash_out = dash_cmd.output().expect("spawn double dash");
    assert!(
        dash_out.status.success(),
        "double-dash scan failed: {}",
        String::from_utf8_lossy(&dash_out.stderr)
    );
    let snap: Snapshot = serde_json::from_str(&fs::read_to_string(&out_json).unwrap()).unwrap();
    assert_eq!(snap.summary.prod_files, 1);
}

#[test]
fn subdirectory_git_scan_strips_prefix_for_churn_and_co_change() {
    let tmp = TempDir::new("git-subdir");
    let repo = tmp.path().join("mono");
    let sub = repo.join("crates/sub");
    fs::create_dir_all(sub.join("src")).unwrap();

    run_git(&repo, &["init", "-b", "main"]);
    run_git(&repo, &["config", "user.email", "test@example.com"]);
    run_git(&repo, &["config", "user.name", "Test User"]);

    for rev in 1..=3 {
        fs::write(sub.join("src/a.rs"), format!("pub fn a() -> u32 {{ {rev} }}\n")).unwrap();
        fs::write(sub.join("src/b.rs"), format!("pub fn b() -> u32 {{ {rev} }}\n")).unwrap();
        run_git(&repo, &["add", "."]);
        run_git(&repo, &["commit", "-m", &format!("rev {rev}")]);
    }

    let snap = scan_repository(
        &sub,
        &ScanOptions {
            git_window: 10,
            ..Default::default()
        },
    )
    .expect("scan subdir");
    assert!(snap.git_available);
    let a = snap.files.iter().find(|f| f.path == "src/a.rs").unwrap();
    assert_eq!(a.churn_commits, 3);
    assert!(
        snap.co_change_pairs
            .iter()
            .any(|p| p.file_a == "src/a.rs" && p.file_b == "src/b.rs" && p.co_changes == 3),
        "expected subdir co-change pair, got {:?}",
        snap.co_change_pairs
    );
}

#[test]
fn cfg_not_test_and_any_test_remain_production_while_cfg_test_and_all_test_are_inline_tests() {
    let tmp = TempDir::new("cfg-test");
    fs::create_dir_all(tmp.path().join("src")).unwrap();
    let code = r#"
#[cfg(not(test))]
pub fn prod_only(x: i32) -> i32 {
    if x > 0 { x } else { -x }
}

#[cfg(any(test, feature = "bench"))]
pub fn shared_bench_helper() -> i32 {
    42
}

#[cfg(test)]
mod unit_tests {
    pub fn helper_a() {}
    pub fn helper_b() {}
}

#[cfg(all(unix, test))]
mod unix_tests {
    pub fn helper_c() {}
}
"#;
    fs::write(tmp.path().join("src/lib.rs"), code).unwrap();

    let snap = scan_repository(
        tmp.path(),
        &ScanOptions {
            git_window: 0,
            ..Default::default()
        },
    )
    .expect("scan");
    let lib = snap.files.iter().find(|f| f.path == "src/lib.rs").unwrap();
    let fn_names: Vec<&str> = lib.functions.iter().map(|f| f.name.as_str()).collect();
    assert!(
        fn_names.contains(&"prod_only"),
        "cfg(not(test)) must stay prod: {fn_names:?}"
    );
    assert!(
        fn_names.contains(&"shared_bench_helper"),
        "cfg(any(test, ...)) must stay prod: {fn_names:?}"
    );
    assert!(!fn_names.contains(&"helper_a"));
    assert!(!fn_names.contains(&"helper_c"));
    assert!(lib.inline_test_loc >= 8);
}

#[test]
fn bounded_read_and_discovered_files_cap() {
    let tmp = TempDir::new("bounds");
    let big = tmp.path().join("big.rs");
    fs::write(&big, vec![b'a'; 200]).unwrap();
    assert!(read_file_bounded(&big, 100).is_err());
    assert_eq!(read_file_bounded(&big, 200).unwrap().len(), 200);

    for i in 0..5 {
        fs::write(tmp.path().join(format!("f{i}.rs")), "pub fn x() {}\n").unwrap();
    }
    let disc = discover_files_with_limit(tmp.path(), &RepoProfile::default(), false, 3).unwrap();
    assert_eq!(disc.files.len(), 3);
    assert!(
        disc.skipped
            .iter()
            .any(|s| s.reason.contains("max discovered files cap")),
        "expected cap diagnostic, got {:?}",
        disc.skipped
    );
}

#[test]
fn glob_match_is_polynomial_on_pathological_double_stars() {
    let start = std::time::Instant::now();
    let pattern = "**/**/**/**/**/**/**/**/**/**/needle.rs";
    let path = "a/b/c/d/e/f/g/h/i/j/k/l/m/n/o/p/q/r/s/t/u/v/w/x/y/z/other.rs";
    assert!(!glob_match(pattern, path));
    assert!(glob_match(pattern, "a/b/c/d/e/f/g/h/i/j/needle.rs"));
    assert!(
        start.elapsed() < std::time::Duration::from_millis(200),
        "glob_match took too long: {:?}",
        start.elapsed()
    );
}

#[test]
fn validation_bom_blanket_dampening_and_ts_brace_eslint() {
    assert_eq!(round2(f64::NAN), 0.0);
    assert_eq!(round2(f64::INFINITY), 0.0);

    let tmp = TempDir::new("validation-bom-ts");
    fs::create_dir_all(tmp.path().join("src")).unwrap();
    fs::create_dir_all(tmp.path().join("tests")).unwrap();

    let bad_budget = tmp.path().join("bad-budget.json");
    fs::write(
        &bad_budget,
        r#"{"schema_version":1,"budgets":{"unknown_limit":10}}"#,
    )
    .unwrap();
    assert!(RepoProfile::load(tmp.path(), Some(&bad_budget)).is_err());

    let neg_budget = tmp.path().join("neg-budget.json");
    fs::write(
        &neg_budget,
        r#"{"schema_version":1,"budgets":{"max_hotspot_score":-5.0}}"#,
    )
    .unwrap();
    assert!(RepoProfile::load(tmp.path(), Some(&neg_budget)).is_err());

    fs::write(
        tmp.path().join("semantic-profile.json"),
        "\u{feff}{\"schema_version\":1,\"cohesive_data_globs\":[\"src/table.rs\"]}\n",
    )
    .unwrap();
    let mut table_src = String::from("\u{feff}#! [allow(clippy::all)]\npub const T: &[u32] = &[\n");
    for i in 0..50 {
        table_src.push_str(&format!("    {i},\n"));
    }
    table_src.push_str("];\n");
    fs::write(tmp.path().join("src/table.rs"), table_src).unwrap();

    fs::write(
        tmp.path().join("tests/allow_in_test.rs"),
        "#![allow(clippy::all)]\n#[test]\nfn t() {}\n",
    )
    .unwrap();

    fs::write(
        tmp.path().join("src/app.ts"),
        "// eslint-disable-next-line\nexport function render(x: string) {\n  const s = \"{{{{}}\"; // {{{\n  // Required for wire protocol logging\n  // eslint-disable-next-line no-console\n  return s + x;\n}\n",
    )
    .unwrap();

    let snap = scan_repository(
        tmp.path(),
        &ScanOptions {
            git_window: 0,
            ..Default::default()
        },
    )
    .expect("scan with BOM");
    let table = snap.files.iter().find(|f| f.path == "src/table.rs").unwrap();
    assert!(!table.parse_fallback, "BOM rust source should parse via syn");
    assert_eq!(table.suppressions.blanket, 1);
    assert_eq!(
        table.dampening_factor, 1.0,
        "blanket suppression must disable cohesive-data dampening"
    );

    let test_file = snap
        .files
        .iter()
        .find(|f| f.path == "tests/allow_in_test.rs")
        .unwrap();
    assert_eq!(test_file.suppressions.total, 0);

    let ts = snap.files.iter().find(|f| f.path == "src/app.ts").unwrap();
    assert_eq!(
        ts.max_nesting_depth, 0,
        "braces in strings/comments must be ignored"
    );
    assert_eq!(ts.suppressions.blanket, 1);
    assert_eq!(ts.suppressions.narrow, 1);
    assert_eq!(ts.suppressions.justified_narrow, 1);

    let mut bad_snap = snap.clone();
    bad_snap.files[0].hotspot_score = f64::NAN;
    let viols = evaluate_budgets(
        &bad_snap,
        Some(&SemanticBudgets {
            max_hotspot_score: Some(100.0),
            ..Default::default()
        }),
    );
    assert!(!viols.is_empty());
}

#[test]
fn detects_scc_bypasses_smeared_writes_and_preserves_clean_leaf_counterevidence() {
    let tmp = TempDir::new("topology-tangled-vs-clean");
    let tangled = tmp.path().join("tangled");
    let clean = tmp.path().join("clean");
    fs::create_dir_all(tangled.join("src")).unwrap();
    fs::create_dir_all(clean.join("src")).unwrap();

    // Tangled fixture: 3-module SCC (billing <-> ledger <-> orders), layer bypass cli -> _raw_store,
    // shortcut triangle cli -> service -> _raw_store, cross_boundary_reach_in, and smeared state_journal.json.
    fs::write(
        tangled.join("semantic-profile.json"),
        r#"{
  "schema_version": 1,
  "layers": [
    { "name": "cli", "globs": ["src/cli.rs"] },
    { "name": "service", "globs": ["src/service.rs", "src/billing.rs", "src/orders.rs", "src/ledger.rs"] },
    { "name": "storage", "globs": ["src/_raw_store.rs", "src/codec.rs"] }
  ],
  "allowed_edges": [
    { "from": "cli", "to": "service" },
    { "from": "service", "to": "storage" }
  ],
  "forbidden_bypasses": [
    { "from": "cli", "to": "storage" }
  ]
}
"#,
    )
    .unwrap();
    fs::write(
        tangled.join("src/codec.rs"),
        "pub fn encode(v: &str) -> String { v.to_string() }\n",
    )
    .unwrap();
    fs::write(
        tangled.join("src/_raw_store.rs"),
        "use crate::codec::encode;\npub fn raw_put(v: &str) -> String { encode(v) }\n",
    )
    .unwrap();
    fs::write(
        tangled.join("src/service.rs"),
        "use crate::_raw_store::raw_put;\nuse crate::billing::bill;\npub fn run() { let _ = raw_put(&bill()); }\n",
    )
    .unwrap();
    fs::write(
        tangled.join("src/cli.rs"),
        "use std::fs;\nuse crate::service::run;\nuse crate::_raw_store::raw_put;\npub fn exec() { run(); let _ = raw_put(\"x\"); let _ = fs::write(\"state_journal.json\", \"cli\"); }\n",
    )
    .unwrap();
    fs::write(
        tangled.join("src/billing.rs"),
        "use std::fs;\nuse crate::orders::order_id;\npub fn bill() -> String { let _ = fs::write(\"state_journal.json\", \"b\"); order_id() }\n",
    )
    .unwrap();
    fs::write(
        tangled.join("src/orders.rs"),
        "use std::fs;\nuse crate::ledger::post;\nuse crate::_raw_store::raw_put;\npub fn order_id() -> String { let _ = raw_put(\"o\"); let _ = fs::write(\"state_journal.json\", \"o\"); post() }\n",
    )
    .unwrap();
    fs::write(
        tangled.join("src/ledger.rs"),
        "use crate::billing::bill;\nuse crate::_raw_store::raw_put;\npub fn post() -> String { let _ = raw_put(\"l\"); bill() }\n",
    )
    .unwrap();

    // Clean fixture: zero SCCs, zero bypasses (shared zero-fan_out leaf types.rs), single writer store.rs.
    fs::write(
        clean.join("semantic-profile.json"),
        r#"{
  "schema_version": 1,
  "layers": [
    { "name": "cli", "globs": ["src/cli.rs"] },
    { "name": "service", "globs": ["src/service.rs"] },
    { "name": "storage", "globs": ["src/store.rs"] }
  ],
  "allowed_edges": [
    { "from": "cli", "to": "service" },
    { "from": "service", "to": "storage" }
  ],
  "forbidden_bypasses": [
    { "from": "cli", "to": "storage" }
  ]
}
"#,
    )
    .unwrap();
    fs::write(
        clean.join("src/types.rs"),
        "pub struct Record { pub id: u64 }\n",
    )
    .unwrap();
    fs::write(
        clean.join("src/store.rs"),
        "use std::fs;\nuse crate::types::Record;\npub fn save(r: &Record) { let _ = fs::write(\"state_journal.json\", r.id.to_string()); }\n",
    )
    .unwrap();
    fs::write(
        clean.join("src/service.rs"),
        "use crate::store::save;\nuse crate::types::Record;\npub fn handle(r: &Record) { save(r); }\n",
    )
    .unwrap();
    fs::write(
        clean.join("src/cli.rs"),
        "use crate::service::handle;\nuse crate::types::Record;\npub fn run() { handle(&Record { id: 1 }); }\n",
    )
    .unwrap();

    let opts = ScanOptions {
        git_window: 0,
        ..Default::default()
    };
    let snap_tangled = scan_repository(&tangled, &opts).expect("scan tangled");
    let snap_clean = scan_repository(&clean, &opts).expect("scan clean");

    assert_eq!(snap_tangled.summary.scc_count, 1);
    assert_eq!(
        snap_tangled.topology.sccs[0].files,
        vec![
            "src/billing.rs".to_string(),
            "src/ledger.rs".to_string(),
            "src/orders.rs".to_string()
        ]
    );
    assert!(snap_tangled.topology.sccs[0].total_est_tokens > 0);

    assert!(snap_tangled.topology.bypasses.iter().any(|b| {
        b.kind == "declared_forbidden_bypass"
            && b.from == "src/cli.rs"
            && b.to == "src/_raw_store.rs"
    }));
    assert!(snap_tangled.topology.bypasses.iter().any(|b| {
        b.kind == "shortcut_triangle" && b.from == "src/cli.rs" && b.to == "src/_raw_store.rs"
    }));
    assert!(
        snap_tangled
            .topology
            .bypasses
            .iter()
            .any(|b| b.kind == "cross_boundary_reach_in" && b.from == "src/cli.rs")
    );

    assert_eq!(snap_tangled.summary.smeared_write_count, 1);
    let smeared = &snap_tangled.topology.smeared_writes[0];
    assert_eq!(smeared.target, "state_journal.json");
    assert_eq!(smeared.writer_count, 3);
    assert_eq!(
        smeared.writers,
        vec![
            "src/billing.rs".to_string(),
            "src/cli.rs".to_string(),
            "src/orders.rs".to_string()
        ]
    );

    assert!(
        snap_tangled
            .topology
            .top_nexus_nodes
            .iter()
            .any(|n| n.path == "src/_raw_store.rs"
                && n.nexus_score >= 3
                && n.transitive_dependents >= 4)
    );

    assert_eq!(snap_clean.summary.scc_count, 0);
    assert_eq!(snap_clean.summary.bypass_count, 0);
    assert_eq!(snap_clean.summary.smeared_write_count, 0);
    let types_clean = snap_clean
        .files
        .iter()
        .find(|f| f.path == "src/types.rs")
        .expect("src/types.rs");
    assert_eq!(types_clean.fan_out, 0);
    assert!(types_clean.fan_in >= 3);
    assert_eq!(types_clean.topology_role, "leaf_utility");
    assert_eq!(types_clean.nexus_score, 0);

    let edges_path = tmp.path().join("edges.json");
    let snap_path = tmp.path().join("snap.json");
    let packet_path = tmp.path().join("packet.json");
    let code = cli::run([
        "semantic-profiler",
        "scan",
        tangled.to_str().unwrap(),
        "--window",
        "0",
        "--output",
        snap_path.to_str().unwrap(),
        "--emit-graph-edges",
        edges_path.to_str().unwrap(),
        "--emit-crw-packet",
        packet_path.to_str().unwrap(),
    ])
    .expect("cli scan tangled");
    assert_eq!(code, 0);

    let parsed_edges: GraphEdgesExport =
        serde_json::from_str(&fs::read_to_string(&edges_path).unwrap()).unwrap();
    assert_eq!(parsed_edges.edge_count, parsed_edges.edges.len());
    assert!(parsed_edges.edges.iter().any(|e| e.kind == "in_scc"));
    assert!(parsed_edges.edges.iter().any(|e| {
        e.kind == "shares_write_target" && e.label.as_deref() == Some("state_journal.json")
    }));
    assert!(parsed_edges.edges.iter().any(|e| {
        e.kind == "bypasses"
            && e.from == "src/cli.rs"
            && e.to == "src/_raw_store.rs"
            && e.label
                .as_deref()
                .is_some_and(|l| l.starts_with("cross_boundary_reach_in:crate::_raw_store"))
    }));

    let packet: CrwHandoffPacket =
        serde_json::from_str(&fs::read_to_string(&packet_path).unwrap()).unwrap();
    assert_eq!(packet.topology.sccs.len(), 1);
    assert_eq!(packet.topology.smeared_writes.len(), 1);
    assert!(!packet.topology.bypasses.is_empty());
}

#[test]
fn phantom_coupling_python_reach_in_rust_path_attr_strata_alias_and_topology_delta() {
    let tmp = TempDir::new("topology-phantom-delta");
    let repo = tmp.path().join("repo");
    fs::create_dir_all(repo.join("pkg")).unwrap();

    run_git(&repo, &["init", "-b", "main"]);
    run_git(&repo, &["config", "user.email", "test@example.com"]);
    run_git(&repo, &["config", "user.name", "Test User"]);

    let bad_layer = tmp.path().join("bad-layer.json");
    fs::write(
        &bad_layer,
        r#"{"schema_version":1,"strata":[{"name":"cli","globs":["pkg/cli.py"]}],"forbidden_bypasses":[{"from":"cli","to":"missing"}]}"#,
    )
    .unwrap();
    assert!(RepoProfile::load(&repo, Some(&bad_layer)).is_err());

    fs::write(
        repo.join("semantic-profile.json"),
        r#"{
  "schema_version": 1,
  "strata": [
    { "name": "api", "globs": ["pkg/api.py"] },
    { "name": "core", "globs": ["pkg/core.py"] },
    { "name": "store", "globs": ["pkg/_store.py"] }
  ],
  "budgets": {
    "max_phantom_coupling_count": 0,
    "max_bypass_count": 0
  }
}
"#,
    )
    .unwrap();

    fs::write(
        repo.join("pkg/api.py"),
        "from .core import run\ndef call():\n    return run()\n",
    )
    .unwrap();
    fs::write(repo.join("pkg/core.py"), "def run():\n    return 1\n").unwrap();
    fs::write(repo.join("pkg/_store.py"), "def save():\n    return True\n").unwrap();
    fs::write(repo.join("pkg/mirror_b.py"), "def sync_b():\n    return 1\n").unwrap();
    run_git(&repo, &["add", "."]);
    run_git(&repo, &["commit", "-m", "base"]);

    let base_snap = scan_repository(
        &repo,
        &ScanOptions {
            git_window: 20,
            ..Default::default()
        },
    )
    .expect("base scan");
    assert_eq!(base_snap.summary.phantom_coupling_count, 0);
    assert_eq!(base_snap.summary.bypass_count, 0);

    for rev in 1..=3 {
        fs::write(
            repo.join("pkg/api.py"),
            format!(
                "from .core import run\nfrom ._store import _raw_put\ndef call():\n    open(\"shared_state.json\", \"w\").write(\"{rev}\")\n    return _raw_put(run())\n"
            ),
        )
        .unwrap();
        fs::write(
            repo.join("pkg/core.py"),
            format!(
                "from pathlib import Path\ndef run():\n    Path(\"shared_state.json\").write_text(\"{rev}\")\n    return {rev}\n"
            ),
        )
        .unwrap();
        fs::write(
            repo.join("pkg/mirror_b.py"),
            format!("def sync_b():\n    return {rev}\n"),
        )
        .unwrap();
        fs::write(
            repo.join("pkg/spliced.rs"),
            "#[path = \"../other/secret.rs\"]\nmod secret;\npub fn k() -> u32 { 1 }\n",
        )
        .unwrap();
        run_git(&repo, &["add", "."]);
        run_git(&repo, &["commit", "-m", &format!("drift {rev}")]);
    }

    let head_snap = scan_repository(
        &repo,
        &ScanOptions {
            git_window: 20,
            ..Default::default()
        },
    )
    .expect("head scan");

    assert!(
        head_snap
            .topology
            .phantom_couplings
            .iter()
            .any(|p| p.file_a == "pkg/core.py" && p.file_b == "pkg/mirror_b.py" && p.co_changes >= 3)
    );
    assert!(
        head_snap
            .topology
            .bypasses
            .iter()
            .any(|b| b.from == "pkg/spliced.rs" && b.kind == "cross_boundary_reach_in")
    );
    assert!(
        head_snap
            .topology
            .bypasses
            .iter()
            .any(|b| b.from == "pkg/api.py" && b.kind == "cross_boundary_reach_in")
    );
    assert!(
        head_snap
            .topology
            .smeared_writes
            .iter()
            .any(|w| w.target == "shared_state.json" && w.writer_count == 2)
    );

    let export = export_graph_edges(&head_snap);
    assert!(export.edges.iter().any(|e| {
        e.kind == "phantom_cochanges" && e.from == "pkg/core.py" && e.to == "pkg/mirror_b.py"
    }));

    let delta = compute_delta(&base_snap, &head_snap);
    assert!(delta.phantom_coupling_count_delta >= 1);
    assert!(delta.bypass_count_delta >= 2);
    assert!(delta.smeared_write_count_delta >= 1);
    assert!(
        delta
            .budget_violations
            .iter()
            .any(|v| v.rule == "max_phantom_coupling_count")
    );
    assert!(
        delta
            .budget_violations
            .iter()
            .any(|v| v.rule == "max_bypass_count")
    );
}

#[test]
fn self_scan_has_zero_sccs_clean_safe_io_leaf_and_graph_edges_cli_error() {
    let snap = scan_repository(
        &manifest_dir(),
        &ScanOptions {
            git_window: 0,
            profile_path: None,
            include_evals: false,
        },
    )
    .expect("self scan");

    assert_eq!(
        snap.summary.scc_count, 0,
        "semantic-profiler must have 0 SCCs, got {:?}",
        snap.topology.sccs
    );
    let safe_io = snap
        .files
        .iter()
        .find(|f| f.path == "src/safe_io.rs")
        .expect("src/safe_io.rs");
    assert_eq!(safe_io.fan_out, 0);
    assert!(safe_io.fan_in >= 3);
    assert_eq!(safe_io.topology_role, "leaf_utility");

    let err = cli::run(["semantic-profiler", "scan", ".", "--graph-edges"])
        .expect_err("missing path must error");
    assert!(
        err.contains("--graph-edges requires a path"),
        "unexpected error: {err}"
    );
}

#[test]
fn smeared_write_false_positive_guards_and_ephemeral_capture_and_role_filtering() {
    let tmp = TempDir::new("write-guards-and-ephemeral");
    fs::create_dir_all(tmp.path().join("src")).unwrap();
    fs::create_dir_all(tmp.path().join("pkg")).unwrap();
    fs::create_dir_all(tmp.path().join("tests")).unwrap();
    fs::create_dir_all(tmp.path().join("evals/case1")).unwrap();

    for name in ["reader_a.py", "reader_b.py"] {
        fs::write(
            tmp.path().join("pkg").join(name),
            concat!(
                "from pathlib import Path\n",
                "def process(out_path, queue, router):\n",
                "    data = open(\"in.txt\", \"r\").read().replace(\"a\", \"b\")\n",
                "    label = \"shared_name.json\"; out_path.write_text(data)\n",
                "    queue.put(\"done\")\n",
                "    router.put(\"/items\", data)\n",
                "    # open(\"commented.json\", \"w\").write(data)\n",
                "    Path(\"stderr.txt\").write_text(\"err\")\n",
                "    Path(\"stdout.txt\").write_text(\"out\")\n",
                "    open(\"prompt.txt\", \"w\").write(\"prompt\")\n",
                "    return label\n",
            ),
        )
        .unwrap();
    }

    fs::write(
        tmp.path().join("src/mod_a.rs"),
        r##"
use std::fs::{self, OpenOptions};
use std::path::Path;

pub fn run_a(id: &str, host: &str, queue: &mut DummyQueue, kv_store: &mut DummyStore) {
    let _ = OpenOptions::new().read(true).write(false).open("readonly.json");
    let _ = fs::write(format!("tmp/{id}"), "x");
    let _ = fs::write(format!("https://{host}"), "x");
    queue.put("done");
    // Ephemeral capture/stream filenames must NOT trigger smeared_writes:
    let _ = fs::write("stdout", "a");
    let _ = fs::write("stderr", "a");
    let _ = fs::write("stdout.txt", "a");
    let _ = fs::write("stderr.txt", "a");
    let _ = fs::write("stdout.bin", "a");
    let _ = fs::write("stderr.bin", "a");
    let _ = fs::write("prompt.txt", "a");
    let _ = fs::write(Path::new("captures").join("stderr.txt"), "a");
    let _ = fs::write("STDOUT.TXT", "a");
    // Real persisted targets shared across mod_a & mod_b MUST trigger smeared_writes:
    let _ = fs::write("state.json", "a");
    let _ = fs::write("manifest.json", "a");
    let _ = fs::write(Path::new("a").join("index.json"), "a");
    let _ = fs::write(format!(r#"ledger/entries_{id}.json"#), "a");
    kv_store.put("orders:state", "a");
    // Single-production-writer target also written by tests/ & evals/ must NOT trigger smeared_writes:
    let _ = fs::write("prod_single_owner.json", "a");
}
"##,
    )
    .unwrap();
    fs::write(
        tmp.path().join("src/mod_b.rs"),
        r##"
use std::fs::{self, OpenOptions};
use std::path::Path;

pub fn run_b(id: &str, host: &str, router: &mut DummyRouter, kv_store: &mut DummyStore) {
    let _ = OpenOptions::new().read(true).write(false).open("readonly.json");
    let _ = fs::write(format!("tmp/{id}"), "y");
    let _ = fs::write(format!("https://{host}"), "y");
    router.put("/items", "y");
    let _ = fs::write("stdout", "b");
    let _ = fs::write("stderr", "b");
    let _ = fs::write("stdout.txt", "b");
    let _ = fs::write("stderr.txt", "b");
    let _ = fs::write("stdout.bin", "b");
    let _ = fs::write("stderr.bin", "b");
    let _ = fs::write("prompt.txt", "b");
    let _ = fs::write(Path::new("captures").join("stderr.txt"), "b");
    let _ = fs::write("STDOUT.TXT", "b");
    let _ = fs::write("state.json", "b");
    let _ = fs::write("manifest.json", "b");
    let _ = fs::write(Path::new("a").join("index.json"), "b");
    let _ = fs::write(format!(r#"ledger/entries_{id}.json"#), "b");
    kv_store.put("orders:state", "b");
}
"##,
    )
    .unwrap();
    // Test and Eval files writing to `prod_single_owner.json` must NEVER enter smeared_writes.
    fs::write(
        tmp.path().join("tests/writer_test.rs"),
        "use std::fs;\n#[test]\nfn t() { let _ = fs::write(\"prod_single_owner.json\", \"t\"); }\n",
    )
    .unwrap();
    fs::write(
        tmp.path().join("evals/case1/runner.rs"),
        "use std::fs;\npub fn run() { let _ = fs::write(\"prod_single_owner.json\", \"e\"); }\n",
    )
    .unwrap();

    let snap = scan_repository(
        tmp.path(),
        &ScanOptions {
            git_window: 0,
            include_evals: true,
            ..Default::default()
        },
    )
    .expect("scan write guards");
    let targets: Vec<&str> = snap
        .topology
        .smeared_writes
        .iter()
        .map(|w| w.target.as_str())
        .collect();

    for expected in [
        "state.json",
        "manifest.json",
        "a/index.json",
        "ledger/entries_",
        "orders:state",
    ] {
        assert!(
            targets.contains(&expected),
            "expected smeared write '{expected}', got {targets:?}"
        );
    }

    for forbidden in [
        "in.txt",
        "shared_name.json",
        "done",
        "/items",
        "commented.json",
        "readonly.json",
        "tmp/",
        "https://",
        "stdout",
        "stderr",
        "stdout.txt",
        "stderr.txt",
        "stdout.bin",
        "stderr.bin",
        "prompt.txt",
        "captures/stderr.txt",
        "STDOUT.TXT",
        "prod_single_owner.json",
    ] {
        assert!(
            !targets.contains(&forbidden),
            "false-positive smeared write target '{forbidden}' in {targets:?}"
        );
    }
}

#[test]
fn rust_external_mod_declarations_emit_edges_and_eliminate_phantom_couplings() {
    let tmp = TempDir::new("rust-mod-edges");
    let repo = tmp.path().join("repo");
    fs::create_dir_all(repo.join("src/sub")).unwrap();
    fs::create_dir_all(repo.join("src/hidden")).unwrap();
    fs::create_dir_all(repo.join("src/nested")).unwrap();

    run_git(&repo, &["init", "-b", "main"]);
    run_git(&repo, &["config", "user.email", "test@example.com"]);
    run_git(&repo, &["config", "user.name", "Test User"]);

    for rev in 1..=3 {
        fs::write(
            repo.join("src/lib.rs"),
            format!(
                "pub mod alpha;\npub(crate) mod sub;\nmod hidden;\npub mod nested;\n#[cfg(test)]\nmod test_support;\npub const REV: u32 = {rev};\n"
            ),
        )
        .unwrap();
        fs::write(
            repo.join("src/main.rs"),
            format!("mod runner;\nfn main() {{ runner::go({rev}); }}\n"),
        )
        .unwrap();
        fs::write(
            repo.join("src/runner.rs"),
            format!("pub fn go(n: u32) -> u32 {{ n + {rev} }}\n"),
        )
        .unwrap();
        fs::write(
            repo.join("src/alpha.rs"),
            format!("pub fn a() -> u32 {{ {rev} }}\n"),
        )
        .unwrap();
        fs::write(
            repo.join("src/sub/mod.rs"),
            format!("pub mod leaf;\npub const SUB_REV: u32 = {rev};\n"),
        )
        .unwrap();
        fs::write(
            repo.join("src/sub/leaf.rs"),
            format!("pub fn leaf() -> u32 {{ {rev} }}\n"),
        )
        .unwrap();
        fs::write(
            repo.join("src/hidden/mod.rs"),
            format!("pub fn h() -> u32 {{ {rev} }}\n"),
        )
        .unwrap();
        // Rust 2018 `src/nested.rs` declaring sibling children in `src/nested/`.
        fs::write(
            repo.join("src/nested.rs"),
            format!("pub mod item;\npub mod helper;\npub const N: u32 = {rev};\n"),
        )
        .unwrap();
        fs::write(
            repo.join("src/nested/item.rs"),
            format!("use super::helper::help;\npub fn item() -> u32 {{ help() + {rev} }}\n"),
        )
        .unwrap();
        fs::write(
            repo.join("src/nested/helper.rs"),
            format!("use crate::alpha::a;\npub fn help() -> u32 {{ a() + {rev} }}\n"),
        )
        .unwrap();
        fs::write(
            repo.join("src/test_support.rs"),
            format!("pub fn fixture() -> u32 {{ {rev} }}\n"),
        )
        .unwrap();
        run_git(&repo, &["add", "."]);
        run_git(&repo, &["commit", "-m", &format!("rev {rev}")]);
    }

    let snap = scan_repository(
        &repo,
        &ScanOptions {
            git_window: 20,
            ..Default::default()
        },
    )
    .expect("scan rust mod repo");

    let export = export_graph_edges(&snap);
    let has_mod_decl = |from: &str, to: &str| {
        export
            .edges
            .iter()
            .any(|e| e.kind == "declares_mod" && e.from == from && e.to == to)
    };

    assert!(has_mod_decl("src/lib.rs", "src/alpha.rs"));
    assert!(has_mod_decl("src/lib.rs", "src/sub/mod.rs"));
    assert!(has_mod_decl("src/lib.rs", "src/hidden/mod.rs"));
    assert!(has_mod_decl("src/lib.rs", "src/nested.rs"));
    assert!(has_mod_decl("src/main.rs", "src/runner.rs"));
    assert!(has_mod_decl("src/sub/mod.rs", "src/sub/leaf.rs"));
    assert!(has_mod_decl("src/nested.rs", "src/nested/item.rs"));
    assert!(has_mod_decl("src/nested.rs", "src/nested/helper.rs"));
    assert!(
        !has_mod_decl("src/lib.rs", "src/test_support.rs"),
        "#[cfg(test)] mod test_support; must not emit a production mod edge"
    );

    // None of the declaring parent <-> child module pairs may appear as phantom couplings!
    for (a, b) in [
        ("src/alpha.rs", "src/lib.rs"),
        ("src/lib.rs", "src/sub/mod.rs"),
        ("src/hidden/mod.rs", "src/lib.rs"),
        ("src/lib.rs", "src/nested.rs"),
        ("src/main.rs", "src/runner.rs"),
        ("src/sub/leaf.rs", "src/sub/mod.rs"),
        ("src/nested.rs", "src/nested/item.rs"),
        ("src/nested.rs", "src/nested/helper.rs"),
    ] {
        assert!(
            !snap
                .topology
                .phantom_couplings
                .iter()
                .any(|p| (p.file_a == a && p.file_b == b) || (p.file_a == b && p.file_b == a)),
            "false phantom coupling between {a} and {b}: {:?}",
            snap.topology.phantom_couplings
        );
    }

    // Rust 2018 `src/nested.rs` declaring both `item` and `helper` must not trigger a false shortcut triangle.
    assert!(
        !snap
            .topology
            .bypasses
            .iter()
            .any(|b| b.kind == "shortcut_triangle" && b.from == "src/nested.rs"),
        "false shortcut_triangle from src/nested.rs: {:?}",
        snap.topology.bypasses
    );
}

#[test]
fn check_subcommand_pass_fail_require_profile_and_base_delta() {
    let tmp = TempDir::new("cli-check");
    let repo = tmp.path().join("repo");
    fs::create_dir_all(repo.join("src")).unwrap();

    run_git(&repo, &["init", "-b", "main"]);
    run_git(&repo, &["config", "user.email", "test@example.com"]);
    run_git(&repo, &["config", "user.name", "Test User"]);

    fs::write(repo.join("src/lib.rs"), "pub mod core;\n").unwrap();
    fs::write(
        repo.join("src/core.rs"),
        "pub fn compute(x: i32) -> i32 {\n    x + 1\n}\n",
    )
    .unwrap();
    run_git(&repo, &["add", "."]);
    run_git(&repo, &["commit", "-m", "initial"]);

    // 1. Without a profile: exits 0 with warning; --require-profile errors.
    let no_prof_out = tmp.path().join("no-prof.json");
    let code_no_prof = cli::run([
        "semantic-profiler",
        "check",
        repo.to_str().unwrap(),
        "--window",
        "10",
        "--json",
        "--output",
        no_prof_out.to_str().unwrap(),
    ])
    .expect("check without profile");
    assert_eq!(code_no_prof, 0);
    let report_no_prof: CheckReport =
        serde_json::from_str(&fs::read_to_string(&no_prof_out).unwrap()).unwrap();
    assert!(report_no_prof.passed);
    assert!(report_no_prof.profile_loaded_from.is_none());
    assert!(!report_no_prof.warnings.is_empty());

    let req_err = cli::run([
        "semantic-profiler",
        "check",
        repo.to_str().unwrap(),
        "--window",
        "10",
        "--require-profile",
    ])
    .expect_err("--require-profile must fail when no profile exists");
    assert!(req_err.contains("--require-profile"), "got: {req_err}");

    // 2. Profile without budgets: passes with warning even with --require-profile.
    let no_budget_profile = tmp.path().join("no-budgets.json");
    fs::write(&no_budget_profile, r#"{"schema_version": 1}"#).unwrap();
    let no_budget_out = tmp.path().join("no-budget-report.json");
    let code_no_budget = cli::run([
        "semantic-profiler",
        "check",
        repo.to_str().unwrap(),
        "--profile",
        no_budget_profile.to_str().unwrap(),
        "--require-profile",
        "--window",
        "10",
        "--json",
        "--output",
        no_budget_out.to_str().unwrap(),
    ])
    .expect("check profile without budgets");
    assert_eq!(code_no_budget, 0);
    let report_no_budget: CheckReport =
        serde_json::from_str(&fs::read_to_string(&no_budget_out).unwrap()).unwrap();
    assert!(report_no_budget.passed);
    assert!(!report_no_budget.budgets_configured);
    assert!(!report_no_budget.warnings.is_empty());

    // 3. Save a baseline snapshot, add semantic-profile.json with passing budgets, run check --base.
    fs::write(
        repo.join("semantic-profile.json"),
        r#"{
  "schema_version": 1,
  "budgets": {
    "max_hotspot_score": 250.0,
    "max_prod_fn_loc": 100,
    "max_blanket_suppressions": 0,
    "max_scc_count": 0,
    "max_smeared_write_count": 0
  }
}
"#,
    )
    .unwrap();
    run_git(&repo, &["add", "."]);
    run_git(&repo, &["commit", "-m", "add profile"]);

    let base_snap_path = tmp.path().join("base.json");
    assert_eq!(
        cli::run([
            "semantic-profiler",
            "scan",
            repo.to_str().unwrap(),
            "--window",
            "10",
            "--output",
            base_snap_path.to_str().unwrap(),
        ])
        .unwrap(),
        0
    );

    fs::write(
        repo.join("src/core.rs"),
        "pub fn compute(x: i32) -> i32 {\n    let y = x + 1;\n    y * 2\n}\n",
    )
    .unwrap();
    run_git(&repo, &["add", "."]);
    run_git(&repo, &["commit", "-m", "grow core"]);

    let pass_json = tmp.path().join("pass.json");
    let pass_txt = tmp.path().join("pass.txt");
    let crw_path = tmp.path().join("crw.json");
    let edges_path = tmp.path().join("edges.json");

    let code_pass_json = cli::run([
        "semantic-profiler",
        "check",
        repo.to_str().unwrap(),
        "--require-profile",
        "--base",
        base_snap_path.to_str().unwrap(),
        "--window",
        "10",
        "--json",
        "--output",
        pass_json.to_str().unwrap(),
        "--emit-crw-packet",
        crw_path.to_str().unwrap(),
        "--emit-graph-edges",
        edges_path.to_str().unwrap(),
    ])
    .expect("check pass json");
    assert_eq!(code_pass_json, 0);

    let pass_report: CheckReport =
        serde_json::from_str(&fs::read_to_string(&pass_json).unwrap()).unwrap();
    assert!(pass_report.passed);
    assert!(pass_report.budget_violations.is_empty());
    assert!(pass_report.budgets_configured);
    assert!(pass_report.delta.is_some());
    assert_eq!(pass_report.delta.as_ref().unwrap().prod_loc_delta, 1);

    let packet: CrwHandoffPacket =
        serde_json::from_str(&fs::read_to_string(&crw_path).unwrap()).unwrap();
    assert!(packet.drift.is_some());
    let edges: GraphEdgesExport =
        serde_json::from_str(&fs::read_to_string(&edges_path).unwrap()).unwrap();
    assert!(
        edges
            .edges
            .iter()
            .any(|e| e.kind == "declares_mod" && e.from == "src/lib.rs" && e.to == "src/core.rs")
    );

    let code_pass_human = cli::run([
        "semantic-profiler",
        "check",
        repo.to_str().unwrap(),
        "--require-profile",
        "--base",
        base_snap_path.to_str().unwrap(),
        "--window",
        "10",
        "--output",
        pass_txt.to_str().unwrap(),
    ])
    .expect("check pass human");
    assert_eq!(code_pass_human, 0);
    let human_text = fs::read_to_string(&pass_txt).unwrap();
    assert!(human_text.contains("semantic-profiler check: PASS"));
    assert!(human_text.contains("delta vs base"));

    // 4. Introduce a blanket suppression to trigger budget violation (exit 2).
    fs::write(
        repo.join("src/core.rs"),
        "#![allow(clippy::all)]\npub fn compute(x: i32) -> i32 {\n    x + 1\n}\n",
    )
    .unwrap();
    let fail_json = tmp.path().join("fail.json");
    let code_fail = cli::run([
        "semantic-profiler",
        "check",
        repo.to_str().unwrap(),
        "--require-profile",
        "--window",
        "10",
        "--json",
        "--output",
        fail_json.to_str().unwrap(),
    ])
    .expect("check fail json");
    assert_eq!(code_fail, 2, "budget violation must exit 2");

    let fail_report: CheckReport =
        serde_json::from_str(&fs::read_to_string(&fail_json).unwrap()).unwrap();
    assert!(!fail_report.passed);
    assert!(
        fail_report
            .budget_violations
            .iter()
            .any(|v| v.rule == "max_blanket_suppressions")
    );
}

#[test]
fn reach_in_resolution_parent_dots_self_super_trimmed_layers_and_upward_inversion() {
    let tmp = TempDir::new("topology-edge-cases");
    fs::create_dir_all(tmp.path().join("pkg/api")).unwrap();
    fs::create_dir_all(tmp.path().join("pkg/storage")).unwrap();
    fs::create_dir_all(tmp.path().join("src/sub")).unwrap();
    fs::create_dir_all(tmp.path().join("web")).unwrap();

    fs::write(
        tmp.path().join("semantic-profile.json"),
        r#"{
  "schema_version": 1,
  "layers": [
    { "name": "  api  ", "globs": ["pkg/api/**"] },
    { "name": " storage ", "globs": ["pkg/storage/**"] }
  ]
}
"#,
    )
    .unwrap();

    fs::write(
        tmp.path().join("pkg/__init__.py"),
        "from . import _internal_ok\n",
    )
    .unwrap();
    fs::write(
        tmp.path().join("pkg/_internal_ok.py"),
        "def ok():\n    return 1\n",
    )
    .unwrap();
    fs::write(
        tmp.path().join("pkg/api/handler.py"),
        "from ..storage import _raw\ndef handle():\n    return _raw.save()\n",
    )
    .unwrap();
    fs::write(
        tmp.path().join("pkg/storage/_raw.py"),
        "from ..api import handler\ndef save():\n    return handler.handle()\n",
    )
    .unwrap();

    fs::write(
        tmp.path().join("src/lib.rs"),
        "pub mod _priv_child;\npub mod alpha;\npub mod sub;\npub use crate::_priv_child;\n",
    )
    .unwrap();
    fs::write(tmp.path().join("src/_priv_child.rs"), "pub fn p() {}\n").unwrap();
    fs::write(tmp.path().join("src/alpha.rs"), "pub fn a() {}\n").unwrap();
    fs::write(
        tmp.path().join("src/sub/mod.rs"),
        "pub mod leaf;\npub use self::leaf::run;\n",
    )
    .unwrap();
    fs::write(
        tmp.path().join("src/sub/leaf.rs"),
        "use self::super::super::alpha::a;\npub fn run() { a(); }\n",
    )
    .unwrap();

    fs::write(
        tmp.path().join("web/index.ts"),
        "export { x } from './_helper';\n",
    )
    .unwrap();
    fs::write(tmp.path().join("web/_helper.ts"), "export const x = 1;\n").unwrap();

    let snap = scan_repository(
        tmp.path(),
        &ScanOptions {
            git_window: 0,
            ..Default::default()
        },
    )
    .expect("scan edge cases");

    let raw_py = snap
        .files
        .iter()
        .find(|f| f.path == "pkg/storage/_raw.py")
        .unwrap();
    assert_eq!(raw_py.layer.as_deref(), Some("storage"));
    assert!(snap.topology.bypasses.iter().any(|b| {
        b.kind == "declared_stratum_violation"
            && b.from == "pkg/storage/_raw.py"
            && b.to == "pkg/api/handler.py"
            && b.detail.contains("upward layer inversion")
    }));

    // `src/sub/leaf.rs` (`self::super::super::alpha::a`) imports `src/alpha.rs` (fan_in = 1);
    // `src/lib.rs` (`pub mod alpha;`) emits a structural `declares_mod` edge without polluting `use` fan_in.
    let alpha = snap
        .files
        .iter()
        .find(|f| f.path == "src/alpha.rs")
        .unwrap();
    assert_eq!(alpha.fan_in, 1);
    let edges = export_graph_edges(&snap);
    assert!(
        edges
            .edges
            .iter()
            .any(|e| e.kind == "imports" && e.from == "src/sub/leaf.rs" && e.to == "src/alpha.rs")
    );
    assert!(
        edges
            .edges
            .iter()
            .any(|e| e.kind == "declares_mod" && e.from == "src/lib.rs" && e.to == "src/alpha.rs")
    );

    for index_file in ["src/lib.rs", "pkg/__init__.py", "web/index.ts"] {
        assert!(
            !snap
                .topology
                .bypasses
                .iter()
                .any(|b| b.kind == "cross_boundary_reach_in" && b.from == index_file),
            "direct sibling re-export in {index_file} should be exempted"
        );
    }
}

#[test]
fn examples_root_profile_and_schema_validate_cleanly() {
    let root = manifest_dir();

    for rel in [
        "examples/rust-service.semantic-profile.json",
        "examples/rust-workspace.semantic-profile.json",
        "semantic-profile.json",
    ] {
        let p = root.join(rel);
        let loaded = RepoProfile::load(&root, Some(&p))
            .unwrap_or_else(|e| panic!("failed to load {rel}: {e}"));
        assert!(loaded.budgets.is_some(), "{rel} should configure budgets");
    }

    let schema_text = fs::read_to_string(root.join("schemas/semantic-profile.schema.json"))
        .expect("read schema");
    let schema: serde_json::Value = serde_json::from_str(&schema_text).expect("valid schema json");
    assert_eq!(
        schema["$schema"].as_str(),
        Some("https://json-schema.org/draft/2020-12/schema")
    );
    assert_eq!(schema["additionalProperties"], serde_json::Value::Bool(false));
    for def in ["LayerSpec", "LayerEdgeRule", "SemanticBudgets"] {
        assert_eq!(
            schema["$defs"][def]["additionalProperties"],
            serde_json::Value::Bool(false),
            "{def} must forbid additionalProperties"
        );
    }
    // Optional nullable fields match Rust Option<T> serde acceptance.
    assert!(
        schema["properties"]["schema_version"]["anyOf"]
            .as_array()
            .unwrap()
            .iter()
            .any(|v| v["type"] == "null")
    );
    assert!(
        schema["properties"]["budgets"]["anyOf"]
            .as_array()
            .unwrap()
            .iter()
            .any(|v| v["type"] == "null")
    );
    assert!(
        schema["$defs"]["SemanticBudgets"]["properties"]["max_scc_count"]["type"]
            .as_array()
            .unwrap()
            .iter()
            .any(|v| v == "null")
    );
}

#[test]
fn mod_child_plus_use_super_has_zero_sccs_and_zero_phantom_coupling() {
    let tmp = TempDir::new("mod-plus-use-super");
    let repo = tmp.path().join("repo");
    fs::create_dir_all(repo.join("src/foo")).unwrap();

    run_git(&repo, &["init", "-b", "main"]);
    run_git(&repo, &["config", "user.email", "test@example.com"]);
    run_git(&repo, &["config", "user.name", "Test User"]);

    for rev in 1..=3 {
        fs::write(
            repo.join("src/lib.rs"),
            format!("pub mod foo;\npub const LIB_REV: u32 = {rev};\n"),
        )
        .unwrap();
        fs::write(
            repo.join("src/foo/mod.rs"),
            format!("pub mod child;\npub struct X {{ pub rev: u32 }}\npub const FOO_REV: u32 = {rev};\n"),
        )
        .unwrap();
        fs::write(
            repo.join("src/foo/child.rs"),
            format!("use super::X;\npub fn make() -> X {{ X {{ rev: {rev} }} }}\n"),
        )
        .unwrap();
        run_git(&repo, &["add", "."]);
        run_git(&repo, &["commit", "-m", &format!("rev {rev}")]);
    }

    let snap = scan_repository(
        &repo,
        &ScanOptions {
            git_window: 20,
            ..Default::default()
        },
    )
    .expect("scan foo/mod + child");
    assert_eq!(
        snap.summary.scc_count, 0,
        "idiomatic mod child; + use super::X must NOT form a fake SCC, got {:?}",
        snap.topology.sccs
    );
    assert!(
        !snap.topology.phantom_couplings.iter().any(|p| {
            (p.file_a == "src/foo/child.rs" && p.file_b == "src/foo/mod.rs")
                || (p.file_a == "src/foo/mod.rs" && p.file_b == "src/foo/child.rs")
        }),
        "mod child; must suppress phantom coupling between foo/mod.rs and foo/child.rs: {:?}",
        snap.topology.phantom_couplings
    );
    let export = export_graph_edges(&snap);
    assert!(
        export
            .edges
            .iter()
            .any(|e| e.kind == "declares_mod" && e.from == "src/foo/mod.rs" && e.to == "src/foo/child.rs")
    );

    // Conversely, if parent ALSO explicitly `use`s from child while child `use super::`, that IS a real SCC.
    fs::write(
        repo.join("src/foo/mod.rs"),
        "pub mod child;\nuse self::child::make;\npub struct X { pub rev: u32 }\npub fn entry() -> X { make() }\n",
    )
    .unwrap();
    let snap_cycle = scan_repository(
        &repo,
        &ScanOptions {
            git_window: 0,
            ..Default::default()
        },
    )
    .expect("scan real cycle");
    assert_eq!(
        snap_cycle.summary.scc_count, 1,
        "explicit mutual use between mod.rs and child.rs must still be detected as an SCC"
    );
}

#[test]
fn check_handles_non_ascii_utf8_commit_empty_budgets_and_cli_guards() {
    let tmp = TempDir::new("cli-audit-guards");
    let repo = tmp.path().join("repo");
    fs::create_dir_all(repo.join("src")).unwrap();
    fs::write(repo.join("src/lib.rs"), "pub fn ok() -> u32 { 1 }\n").unwrap();

    // 1. Empty `"budgets": {}` must report budgets_configured == false and warn cleanly.
    fs::write(
        repo.join("semantic-profile.json"),
        r#"{"schema_version": 1, "budgets": {}}"#,
    )
    .unwrap();
    let empty_budget_report = tmp.path().join("empty-budgets.json");
    let code = cli::run([
        "semantic-profiler",
        "check",
        repo.to_str().unwrap(),
        "--window",
        "0",
        "--require-profile",
        "--json",
        "--output",
        empty_budget_report.to_str().unwrap(),
    ])
    .expect("check empty budgets");
    assert_eq!(code, 0);
    let report: CheckReport =
        serde_json::from_str(&fs::read_to_string(&empty_budget_report).unwrap()).unwrap();
    assert!(!report.budgets_configured);
    assert!(
        report
            .warnings
            .iter()
            .any(|w| w.contains("defines no budgets")),
        "expected no-budgets warning, got {:?}",
        report.warnings
    );

    // 2. Non-ASCII multi-byte UTF-8 commit in --base snapshot must not panic in human formatter.
    let mut base_snap = scan_repository(
        &repo,
        &ScanOptions {
            git_window: 0,
            ..Default::default()
        },
    )
    .expect("base scan");
    base_snap.commit = Some("ééééééééééééééé".to_string());
    let base_path = tmp.path().join("utf8-base.json");
    fs::write(&base_path, serde_json::to_string_pretty(&base_snap).unwrap()).unwrap();

    let human_out = tmp.path().join("human.txt");
    let code_utf8 = cli::run([
        "semantic-profiler",
        "check",
        repo.to_str().unwrap(),
        "--window",
        "0",
        "--base",
        base_path.to_str().unwrap(),
        "--output",
        human_out.to_str().unwrap(),
    ])
    .expect("check with utf8 commit base");
    assert_eq!(code_utf8, 0);
    let rendered = fs::read_to_string(&human_out).unwrap();
    assert!(rendered.contains("éééééééééééé"), "got: {rendered}");

    // 3. Reject duplicate singleton flags, flag-as-value, non-regular output path, and empty layer glob.
    let dup_err = cli::run([
        "semantic-profiler",
        "check",
        repo.to_str().unwrap(),
        "--window",
        "0",
        "--window",
        "10",
    ])
    .expect_err("duplicate --window must fail");
    assert!(dup_err.contains("duplicate option"), "got: {dup_err}");

    let flag_val_err = cli::run([
        "semantic-profiler",
        "check",
        repo.to_str().unwrap(),
        "--base",
        "--json",
    ])
    .expect_err("flag-as-value must fail");
    assert!(
        flag_val_err.contains("option-like value"),
        "got: {flag_val_err}"
    );

    let dir_out = tmp.path().join("existing-dir");
    fs::create_dir_all(&dir_out).unwrap();
    let non_reg_err = cli::run([
        "semantic-profiler",
        "check",
        repo.to_str().unwrap(),
        "--window",
        "0",
        "--output",
        dir_out.to_str().unwrap(),
    ])
    .expect_err("writing to directory must fail");
    assert!(
        non_reg_err.contains("non-regular file"),
        "got: {non_reg_err}"
    );

    let blank_glob_profile = tmp.path().join("blank-glob.json");
    fs::write(
        &blank_glob_profile,
        r#"{"schema_version":1,"layers":[{"name":"api","globs":["   "]}]}"#,
    )
    .unwrap();
    assert!(RepoProfile::load(&repo, Some(&blank_glob_profile)).is_err());
}

#[test]
fn crate_anchored_imports_do_not_leak_across_crates_and_path_attr_resolves_module_relative() {
    let tmp = TempDir::new("scope-and-path-attr");
    fs::create_dir_all(tmp.path().join("crates/a/src")).unwrap();
    fs::create_dir_all(tmp.path().join("crates/b/src")).unwrap();
    fs::create_dir_all(tmp.path().join("crates/c/src/local")).unwrap();
    fs::create_dir_all(tmp.path().join("crates/c/src/sub/local/impl_mod")).unwrap();
    fs::create_dir_all(tmp.path().join("crates/c/src/sub/inner")).unwrap();

    // Crate A references an unresolved `crate::ghost_helper::run`; Crate B has `ghost_helper.rs`.
    // Crate-anchored import MUST NOT leak across crates via global_stem_map!
    fs::write(
        tmp.path().join("crates/a/src/lib.rs"),
        "use crate::ghost_helper::run;\npub fn entry() { run(); }\n",
    )
    .unwrap();
    fs::write(
        tmp.path().join("crates/b/src/ghost_helper.rs"),
        "pub fn run() {}\n",
    )
    .unwrap();

    // Crate C: `#[path = "local/impl_mod/mod.rs"]` inside `src/sub/mod.rs` must resolve to
    // `crates/c/src/sub/local/impl_mod/mod.rs` (module-relative) rather than `crates/c/src/local/impl_mod.rs`,
    // and inline `mod inner { #[path = "leaf.rs"] pub mod leaf; }` must resolve to `crates/c/src/sub/inner/leaf.rs`.
    fs::write(
        tmp.path().join("crates/c/src/local/impl_mod.rs"),
        "pub fn wrong() {}\n",
    )
    .unwrap();
    fs::write(
        tmp.path().join("crates/c/src/sub/mod.rs"),
        concat!(
            "#[path = \"local/impl_mod/mod.rs\"]\n",
            "pub mod impl_mod;\n",
            "pub mod inner {\n",
            "    #[path = \"leaf.rs\"]\n",
            "    pub mod leaf;\n",
            "}\n",
        ),
    )
    .unwrap();
    fs::write(
        tmp.path().join("crates/c/src/sub/local/impl_mod/mod.rs"),
        "pub fn right() {}\n",
    )
    .unwrap();
    fs::write(
        tmp.path().join("crates/c/src/sub/inner/leaf.rs"),
        "pub fn leaf_fn() {}\n",
    )
    .unwrap();

    let snap = scan_repository(
        tmp.path(),
        &ScanOptions {
            git_window: 0,
            ..Default::default()
        },
    )
    .expect("scan multi-crate");
    let export = export_graph_edges(&snap);

    assert!(
        !export.edges.iter().any(|e| {
            e.from == "crates/a/src/lib.rs" && e.to == "crates/b/src/ghost_helper.rs"
        }),
        "crate-anchored import leaked across crates: {:?}",
        export.edges
    );
    assert!(
        export.edges.iter().any(|e| {
            e.kind == "declares_mod"
                && e.from == "crates/c/src/sub/mod.rs"
                && e.to == "crates/c/src/sub/local/impl_mod/mod.rs"
        }),
        "#[path] must resolve module-relative and strip /mod.rs: {:?}",
        export.edges
    );
    assert!(
        export.edges.iter().any(|e| {
            e.kind == "declares_mod"
                && e.from == "crates/c/src/sub/mod.rs"
                && e.to == "crates/c/src/sub/inner/leaf.rs"
        }),
        "inline mod inner #[path] must honor mod_stack: {:?}",
        export.edges
    );
}

#[test]
fn python_multiline_signatures_and_param_counts_match_syntax() {
    let tmp = TempDir::new("py-multiline-sigs");
    fs::create_dir_all(tmp.path().join("pkg")).unwrap();

    // 1. Multiline `def` with 16 params (>12 lines), nested generic types, tuple/call/string/lambda
    //    defaults, comments containing `)` and `:`, `/` & `*` separators, `*args`, `**kwargs`,
    //    multiline return annotation, `)` at def_indent, and a 50-line body.
    let mut src = String::from(
        concat!(
            "def long_multiline(\n",
            "    p1: int,\n",
            "    p2: str = \",\",\n",
            "    /,\n",
            "    p3: dict[str, tuple[int, str]] = {},\n",
            "    p4: Callable[[int, str], dict[str, Any]] = default_fn(1, 2),\n",
            "    p5: tuple[int, int] = (1, 2),  # comment with ) and : and ,\n",
            "    p6: str = \") -> None:\",\n",
            "    p7: Callable[[int, int], int] = lambda a, b: a + b,\n",
            "    *,\n",
            "    p8: int = 8,\n",
            "    p9: int = 9,\n",
            "    p10: int = 10,\n",
            "    p11: int = 11,\n",
            "    p12: int = 12,\n",
            "    p13: int = 13,\n",
            "    p14: int = 14,\n",
            "    *args: int,\n",
            "    **kwargs: Any,\n",
            ") -> tuple[\n",
            "    int,\n",
            "    str,\n",
            "]:  # trailing header comment\n",
        ),
    );
    // Header is 23 lines (lines 1..=23). Add 50 body lines (lines 24..=73) -> total loc = 73.
    for i in 0..49 {
        src.push_str(&format!("    v{i} = p1 + {i}\n"));
    }
    src.push_str("    return (p1, p2)\n\n");

    // 2. Async method with typed `self`, `cls` classmethod, multiline return annotation, and PEP 695 type params.
    src.push_str(concat!(
        "class Service:\n",
        "    async def fetch(\n",
        "        self: \"Service\",\n",
        "        url: str,\n",
        "        headers: dict[str, str] = {\"a\": \"b,c\"},\n",
        "        timeout: tuple[float, float] = (1.0, 5.0),\n",
        "    ) -> tuple[\n",
        "        int,\n",
        "        bytes,\n",
        "    ]:\n",
        "        status = 200\n",
        "        if url:\n",
        "            status = 201\n",
        "        return (status, b\"ok\")\n",
        "\n",
        "    @classmethod\n",
        "    def build(\n",
        "        cls: type[\"Service\"],\n",
        "        name: str,\n",
        "    ) -> \"Service\":\n",
        "        return cls()\n",
        "\n",
        "def generic_pair[T, U](\n",
        "    first: T,\n",
        "    second: U,\n",
        ") -> tuple[T, U]:\n",
        "    return (first, second)\n",
    ));

    fs::write(tmp.path().join("pkg/sigs.py"), src).unwrap();

    let snap = scan_repository(
        tmp.path(),
        &ScanOptions {
            git_window: 0,
            ..Default::default()
        },
    )
    .expect("scan python multiline sigs");

    let py = snap
        .files
        .iter()
        .find(|f| f.path == "pkg/sigs.py")
        .expect("pkg/sigs.py");

    let long_fn = py
        .functions
        .iter()
        .find(|f| f.name == "long_multiline")
        .expect("long_multiline");
    assert_eq!(long_fn.start_line, 1);
    assert_eq!(long_fn.end_line, 73);
    assert_eq!(long_fn.loc, 73);
    assert_eq!(
        long_fn.param_count, 16,
        "14 named params + *args + **kwargs (excluding / and *)"
    );

    let fetch = py
        .functions
        .iter()
        .find(|f| f.name == "fetch")
        .expect("fetch");
    assert_eq!(fetch.loc, 13);
    assert_eq!(fetch.param_count, 3, "typed self must be excluded");
    assert_eq!(fetch.max_nesting_depth, 1);

    let build = py
        .functions
        .iter()
        .find(|f| f.name == "build")
        .expect("build");
    assert_eq!(build.loc, 5);
    assert_eq!(build.param_count, 1, "typed cls must be excluded");

    let generic = py
        .functions
        .iter()
        .find(|f| f.name == "generic_pair")
        .expect("generic_pair");
    assert_eq!(generic.loc, 5);
    assert_eq!(generic.param_count, 2);
}

#[test]
fn python_multiline_strings_continuations_inline_and_nested_defs() {
    let tmp = TempDir::new("py-strings-and-cont");
    fs::create_dir_all(tmp.path().join("pkg")).unwrap();

    let src = concat!(
        "def with_docstrings(x: int) -> str:\n",               // 1
        "    \"\"\"\n",                                          // 2
        "Flush-left docstring line.\n",                          // 3
        "from fake_pkg import _secret_helper\n",                 // 4
        "def fake_inside_double_triple():\n",                    // 5
        "    return 999\n",                                      // 6
        "\"\"\"\n",                                              // 7
        "    if x > 0:\n",                                       // 8
        "        sql = '''\n",                                   // 9
        "SELECT *\n",                                            // 10
        "def fake_inside_single_triple():\n",                    // 11
        "if fake_branch:\n",                                     // 12
        "    for z in items:\n",                                 // 13
        "'''\n",                                                 // 14
        "        if x > 1:\n",                                   // 15
        "            return sql\n",                              // 16
        "    return \"\"\n",                                     // 17
        "\n",                                                    // 18
        "def with_flush_left_continuations(a, b):\n",            // 19
        "    items = [\n",                                       // 20
        "        a,\n",                                          // 21
        "        b,\n",                                          // 22
        "]\n",                                                   // 23
        "    total = a + \\\n",                                  // 24
        "b\n",                                                   // 25
        "    return (items, total)\n",                           // 26
        "\n",                                                    // 27
        "def one_liner(x): return x + 1\n",                      // 28
        "def second_one_liner(x, y): return x * y\n",            // 29
        "\n",                                                    // 30
        "def outer(n: int) -> int:\n",                           // 31
        "    def inner(\n",                                      // 32
        "        k: int,\n",                                     // 33
        "    ) -> int:\n",                                       // 34
        "        return k * 2\n",                                // 35
        "    return inner(n) + 1\n",                             // 36
    );
    fs::write(tmp.path().join("pkg/body_cases.py"), src).unwrap();

    let snap = scan_repository(
        tmp.path(),
        &ScanOptions {
            git_window: 0,
            ..Default::default()
        },
    )
    .expect("scan python body cases");

    let py = snap
        .files
        .iter()
        .find(|f| f.path == "pkg/body_cases.py")
        .expect("pkg/body_cases.py");

    let fn_names: Vec<&str> = py.functions.iter().map(|f| f.name.as_str()).collect();
    assert_eq!(
        fn_names,
        vec![
            "with_docstrings",
            "with_flush_left_continuations",
            "one_liner",
            "second_one_liner",
            "outer",
            "inner",
        ],
        "fake defs inside triple-quoted strings must not be reported"
    );
    assert!(
        py.internal_imports.is_empty() && py.reach_ins.is_empty(),
        "fake `from ... import ...` inside triple-quoted string must be ignored: imports={:?}, reach_ins={:?}",
        py.internal_imports,
        py.reach_ins
    );

    let doc_fn = &py.functions[0];
    assert_eq!((doc_fn.start_line, doc_fn.end_line, doc_fn.loc), (1, 17, 17));
    assert_eq!(
        doc_fn.max_nesting_depth, 2,
        "flush-left triple-quoted string must not corrupt block_indents or add fake nesting"
    );

    let cont_fn = &py.functions[1];
    assert_eq!(
        (cont_fn.start_line, cont_fn.end_line, cont_fn.loc),
        (19, 26, 8)
    );

    let one = &py.functions[2];
    assert_eq!((one.start_line, one.end_line, one.loc, one.param_count), (28, 28, 1, 1));

    let two = &py.functions[3];
    assert_eq!((two.start_line, two.end_line, two.loc, two.param_count), (29, 29, 1, 2));

    let outer = &py.functions[4];
    assert_eq!((outer.start_line, outer.end_line, outer.loc), (31, 36, 6));

    let inner = &py.functions[5];
    assert_eq!(
        (inner.start_line, inner.end_line, inner.loc, inner.param_count),
        (32, 35, 4, 1)
    );
}

#[test]
fn python_pep701_fstrings_tstrings_raw_escapes_nested_lambda_and_eof_resilience() {
    let tmp = TempDir::new("py-pep701-and-edge-cases");
    fs::create_dir_all(tmp.path().join("pkg")).unwrap();

    // 1. PEP 701 f-strings (nested same-quote with unbalanced `(`, format specs with `#` and nested
    //    `{width}`, multiline `{...}` with nested triple-quoted `def fake():`), Python 3.14 t-strings,
    //    raw string escapes (`r"\""`, `r"\\"`), escaped triple quotes (`"""foo\"""bar"""`),
    //    nested `lambda` inside `lambda` default, >256 bytes of whitespace before param name,
    //    multiline inline suite (`def f(x): return (\n 1 + 2\n)`), and parenthesized/tabbed control headers.
    let long_ws = " ".repeat(300);
    let mut code = String::from(concat!(
        "async def uses_pep701(text: str, d: dict[str, str], width: int) -> str:\n", // 1
        "    head = f\"{text.split(\"(\")[0]}\"\n",                                  // 2
        "    fmt = f\"{255:#x} {text:>{width}} {{escaped}}\"\n",                     // 3
        "    tpl = t\"{text.split(\"(\")[0]}\"\n",                                   // 4
        "    multi = f\"{\n",                                                        // 5
        "        '''\n",                                                             // 6
        "def fake_in_fstring():\n",                                                  // 7
        "from fake_fstring_mod import _leak\n",                                      // 8
        "'''\n",                                                                     // 9
        "    }\"\n",                                                                 // 10
        "    raw1 = r\"\\\"\"\n",                                                    // 11
        "    raw2 = r\"\\\\\"\n",                                                    // 12
        "    esc_triple = \"\"\"foo\\\"\"\"bar\"\"\"\n",                             // 13
        "    if\ttext:\n",                                                           // 14
        "        async\twith(open_ctx()):\n",                                        // 15
        "            async\tfor item in stream:\n",                                  // 16
        "                try :\n",                                                   // 17
        "                    match(width):\n",                                       // 18
        "                        pass\n",                                            // 19
        "    return head + fmt + str(tpl) + multi + raw1 + raw2 + esc_triple\n",     // 20
        "\n",                                                                        // 21
        "def after_pep701(\n",                                                       // 22
        "    x=f\"{d[\"a,b\"]}\",\n",                                                // 23
        "    y=1,\n",                                                                // 24
        ") -> int:\n",                                                               // 25
        "    return y\n",                                                            // 26
        "\n",                                                                        // 27
        "def nested_lambda_default(\n",                                              // 28
        "    fn=lambda a=lambda x, y: x + y, b=1: a(b, b),\n",                       // 29
        "    z=2,\n",                                                                // 30
        ") -> int:\n",                                                               // 31
        "    return fn() + z\n",                                                     // 32
        "\n",                                                                        // 33
        "def multiline_inline_suite(x: int) -> int: return (\n",                     // 34
        "    x + 1\n",                                                               // 35
        ")\n",                                                                       // 36
        "\n",                                                                        // 37
    ));
    // Add function with >256 bytes of leading whitespace before a parameter name.
    code.push_str("def wide_ws_param(\n"); // 38
    code.push_str(&format!("{long_ws}self,\n")); // 39
    code.push_str(&format!("{long_ws}alpha: int,\n")); // 40
    code.push_str(") -> int:\n"); // 41
    code.push_str("    return alpha\n"); // 42

    fs::write(tmp.path().join("pkg/pep701.py"), code).unwrap();

    // 2. Unclosed/truncated EOF inputs must never panic or loop.
    fs::write(
        tmp.path().join("pkg/truncated.py"),
        concat!(
            "def truncated_sig(\n",
            "    a: int,\n",
            "    b: str = f\"{x:10\n",
        ),
    )
    .unwrap();
    fs::write(
        tmp.path().join("pkg/unclosed_str.py"),
        concat!(
            "def ok_before():\n",
            "    s = f\"unclosed\n",
            "def ok_after(x):\n",
            "    return x\n",
        ),
    )
    .unwrap();

    let snap = scan_repository(
        tmp.path(),
        &ScanOptions {
            git_window: 0,
            ..Default::default()
        },
    )
    .expect("scan pep701 and truncated");

    let py = snap
        .files
        .iter()
        .find(|f| f.path == "pkg/pep701.py")
        .expect("pkg/pep701.py");

    let names: Vec<&str> = py.functions.iter().map(|f| f.name.as_str()).collect();
    assert_eq!(
        names,
        vec![
            "uses_pep701",
            "after_pep701",
            "nested_lambda_default",
            "multiline_inline_suite",
            "wide_ws_param",
        ],
        "PEP 701 f-string must neither swallow subsequent defs nor spawn phantom defs"
    );
    assert!(
        py.internal_imports.is_empty() && py.reach_ins.is_empty(),
        "fake import inside triple-quoted string inside f-string must be ignored"
    );

    let f0 = &py.functions[0];
    assert_eq!((f0.start_line, f0.end_line, f0.loc, f0.param_count), (1, 20, 20, 3));
    assert_eq!(
        f0.max_nesting_depth, 5,
        "if\\t, async\\twith(, async\\tfor, try :, match( must all register nesting levels"
    );

    let f1 = &py.functions[1];
    assert_eq!((f1.start_line, f1.end_line, f1.loc, f1.param_count), (22, 26, 5, 2));

    let f2 = &py.functions[2];
    assert_eq!((f2.start_line, f2.end_line, f2.loc, f2.param_count), (28, 32, 5, 2));

    let f3 = &py.functions[3];
    assert_eq!((f3.start_line, f3.end_line, f3.loc, f3.param_count), (34, 36, 3, 1));

    let f4 = &py.functions[4];
    assert_eq!((f4.start_line, f4.end_line, f4.loc, f4.param_count), (38, 42, 5, 1));

    let unclosed = snap
        .files
        .iter()
        .find(|f| f.path == "pkg/unclosed_str.py")
        .expect("pkg/unclosed_str.py");
    let unclosed_names: Vec<&str> = unclosed.functions.iter().map(|f| f.name.as_str()).collect();
    assert_eq!(unclosed_names, vec!["ok_before", "ok_after"]);

    let trunc = snap
        .files
        .iter()
        .find(|f| f.path == "pkg/truncated.py")
        .expect("pkg/truncated.py");
    assert_eq!(trunc.functions.len(), 1);
    assert_eq!(trunc.functions[0].name, "truncated_sig");
}

#[test]
fn python_stdlib_imports_and_index_py_do_not_create_false_sccs() {
    let tmp = TempDir::new("py-stdlib-and-index");
    let pkg = tmp.path().join("src/my_pkg/companions");
    let lib = tmp.path().join("src/my_pkg/library");
    let web = tmp.path().join("web/components");
    fs::create_dir_all(&pkg).unwrap();
    fs::create_dir_all(&lib).unwrap();
    fs::create_dir_all(&web).unwrap();

    // Package __init__.py re-exports leaf contracts.py, which only imports Python stdlib.
    fs::write(
        pkg.join("__init__.py"),
        "from .contracts import ServiceProtocol\n__all__ = ['ServiceProtocol']\n",
    )
    .unwrap();
    fs::write(
        pkg.join("contracts.py"),
        "from pathlib import Path\nfrom typing import Protocol\n\nclass ServiceProtocol(Protocol):\n    def read(self, p: Path) -> str: ...\n",
    )
    .unwrap();

    // Python package with both __init__.py and a regular module named index.py;
    // index.py imports config.py, while config.py only imports stdlib (os, pathlib).
    fs::write(
        lib.join("__init__.py"),
        "from .index import SearchIndex\n__all__ = ['SearchIndex']\n",
    )
    .unwrap();
    fs::write(
        lib.join("config.py"),
        "import os\nfrom pathlib import Path\n\ndef default_root() -> Path:\n    return Path(os.getcwd())\n",
    )
    .unwrap();
    fs::write(
        lib.join("index.py"),
        "from .config import default_root\n\nclass SearchIndex:\n    def root(self):\n        return default_root()\n",
    )
    .unwrap();

    // JS/TS directory index.ts must still resolve as a package entrypoint.
    fs::write(web.join("index.ts"), "export const Widget = 1;\n").unwrap();
    fs::write(
        tmp.path().join("web/app.ts"),
        "import { Widget } from './components';\nexport const x = Widget;\n",
    )
    .unwrap();

    // Non-standard Python virtualenv directories (PEP 405 pyvenv.cfg, e.g. .venv2) must be skipped.
    let venv2 = tmp.path().join(".venv2/Lib/site-packages/third_party");
    fs::create_dir_all(&venv2).unwrap();
    fs::write(tmp.path().join(".venv2/pyvenv.cfg"), "home = /usr/bin\n").unwrap();
    fs::write(venv2.join("a.py"), "from .b import B\n").unwrap();
    fs::write(venv2.join("b.py"), "from .a import A\n").unwrap();

    let snap = scan_repository(
        tmp.path(),
        &ScanOptions {
            git_window: 0,
            ..Default::default()
        },
    )
    .expect("scan python stdlib and index.py");

    assert!(
        snap.topology.sccs.is_empty(),
        "stdlib imports and Python index.py must not produce false SCCs: {:?}",
        snap.topology.sccs
    );

    let edges = export_graph_edges(&snap);
    let import_edges: Vec<(&str, &str)> = edges
        .edges
        .iter()
        .filter(|e| e.kind == "imports")
        .map(|e| (e.from.as_str(), e.to.as_str()))
        .collect();

    assert!(
        import_edges.contains(&(
            "src/my_pkg/companions/__init__.py",
            "src/my_pkg/companions/contracts.py"
        )),
        "expected __init__.py -> contracts.py, got {import_edges:?}"
    );
    assert!(
        !import_edges.contains(&(
            "src/my_pkg/companions/contracts.py",
            "src/my_pkg/companions/__init__.py"
        )),
        "stdlib imports must not fabricate contracts.py -> __init__.py: {import_edges:?}"
    );
    assert!(
        import_edges.contains(&(
            "src/my_pkg/library/index.py",
            "src/my_pkg/library/config.py"
        )),
        "expected library/index.py -> library/config.py, got {import_edges:?}"
    );
    assert!(
        !import_edges.contains(&(
            "src/my_pkg/library/config.py",
            "src/my_pkg/library/index.py"
        )),
        "Python index.py must not alias directory and fabricate config.py -> index.py: {import_edges:?}"
    );
    assert!(
        !import_edges.contains(&(
            "src/my_pkg/library/config.py",
            "src/my_pkg/library/__init__.py"
        )),
        "stdlib imports must not fabricate config.py -> __init__.py: {import_edges:?}"
    );
    assert!(
        import_edges.contains(&("web/app.ts", "web/components/index.ts")),
        "TypeScript directory index.ts resolution must be preserved: {import_edges:?}"
    );
}
