//! Unit and end-to-end integration tests for the `ecosystem` cross-repo graph scanner.

use semantic_profiler::cli;
use semantic_profiler::ecosystem::manifests::{
    normalize_git_url, normalize_python_name, parse_cargo_lock, parse_cargo_toml,
    parse_domain_json, parse_pyproject_toml,
};
use semantic_profiler::ecosystem::model::{
    ECOSYSTEM_GRAPH_FORMAT, EcosystemGraph, EcosystemScanOptions,
};
use semantic_profiler::ecosystem::scan_ecosystem;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::sync::atomic::{AtomicUsize, Ordering};

#[cfg(windows)]
use std::os::windows::process::CommandExt;

#[cfg(windows)]
const CREATE_NO_WINDOW: u32 = 0x0800_0000;

static NEXT_ECO_TMP: AtomicUsize = AtomicUsize::new(0);

struct TempDir(PathBuf);

impl TempDir {
    fn new(name: &str) -> Self {
        let dir = std::env::temp_dir().join(format!(
            "semantic-profiler-eco-test-{}-{}-{}",
            name,
            std::process::id(),
            NEXT_ECO_TMP.fetch_add(1, Ordering::Relaxed)
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

fn run_git(dir: &Path, args: &[&str]) -> String {
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
    String::from_utf8_lossy(&out.stdout).trim().to_string()
}

fn init_git_repo(dir: &Path, remote_url: &str) {
    run_git(dir, &["init", "-b", "main"]);
    run_git(dir, &["config", "user.name", "Test Bot"]);
    run_git(dir, &["config", "user.email", "test@example.com"]);
    run_git(dir, &["remote", "add", "origin", remote_url]);
}

fn commit_all(dir: &Path, msg: &str) -> String {
    run_git(dir, &["add", "."]);
    run_git(dir, &["commit", "-m", msg]);
    run_git(dir, &["rev-parse", "HEAD"])
}

#[test]
fn manifest_parsers_handle_cargo_lock_pyproject_and_domain() {
    assert_eq!(
        normalize_git_url("https://github.com/Example/Repo.git/"),
        "github.com/example/repo"
    );
    assert_eq!(
        normalize_git_url(concat!("git", "@", "github.com:Example/Repo.git")),
        "github.com/example/repo"
    );
    assert_eq!(
        normalize_git_url(concat!("ssh://git", "@", "github.com/Example/Repo")),
        "github.com/example/repo"
    );
    assert_eq!(normalize_python_name("My_Core.Lib--Pkg"), "my-core-lib-pkg");

    let cargo = parse_cargo_toml(
        r#"
[package]
name = "svc-api"
version = "0.2.0"

[workspace]
members = [
    "crates/a",
    "crates/b",
]

[dependencies]
core-v1 = { package = "core-lib", git = "https://github.com/example/core-lib", rev = "1111111111111111111111111111111111111111" }
local-dep = {
    path = "../local-crate",
    optional = true,
}

[dev-dependencies.test-helper]
git = "https://github.com/example/test-helper.git"
branch = "main"

[workspace.dependencies]
shared-bus = { git = "https://github.com/example/shared-bus", tag = "v1.0.0" }
"#,
    );
    assert_eq!(cargo.package_name.as_deref(), Some("svc-api"));
    assert_eq!(cargo.workspace_members, vec!["crates/a", "crates/b"]);
    assert_eq!(cargo.dependencies.len(), 4);
    assert!(cargo.dependencies.iter().any(|d| {
        d.alias == "core-v1"
            && d.package_name == "core-lib"
            && d.section == "dependencies"
            && d.rev.as_deref() == Some("1111111111111111111111111111111111111111")
    }));
    assert!(cargo.dependencies.iter().any(|d| {
        d.package_name == "test-helper"
            && d.section == "dev-dependencies"
            && d.branch.as_deref() == Some("main")
    }));
    assert!(cargo.dependencies.iter().any(|d| {
        d.package_name == "shared-bus"
            && d.section == "workspace.dependencies"
            && d.tag.as_deref() == Some("v1.0.0")
    }));

    let locks = parse_cargo_lock(
        r#"
version = 4

[[package]]
name = "core-lib"
version = "0.1.0"
source = "git+https://github.com/example/core-lib.git?rev=11111111#1111111111111111111111111111111111111111"

[[package]]
name = "serde"
version = "1.0.228"
source = "registry+https://github.com/rust-lang/crates.io-index"
"#,
    );
    assert_eq!(locks.len(), 1);
    assert_eq!(locks[0].name, "core-lib");
    assert_eq!(locks[0].normalized_git_url, "github.com/example/core-lib");
    assert_eq!(
        locks[0].resolved_sha,
        "1111111111111111111111111111111111111111"
    );

    let py = parse_pyproject_toml(
        r#"
[project]
name = "py_client"
version = "0.3.0"
dependencies = [
    "py_core[fast]>=0.1; python_version >= '3.11'",
    "helper-pkg @ git+https://github.com/example/helper-pkg.git@abcdef1234567",
]

[project.optional-dependencies]
dev = ["py.extra>=1.0"]
"#,
    );
    assert_eq!(py.package_name.as_deref(), Some("py_client"));
    assert_eq!(py.dependencies.len(), 3);
    assert_eq!(py.dependencies[0].normalized_name, "py-core");
    assert!(!py.dependencies[0].is_optional);
    assert_eq!(
        py.dependencies[1].git_rev.as_deref(),
        Some("abcdef1234567")
    );
    assert!(py.dependencies[2].is_optional);
    assert_eq!(py.dependencies[2].normalized_name, "py-extra");

    let dom = parse_domain_json(
        r#"{"id": "domain-app", "version": "2", "requires_domains": ["domain-base"]}"#,
    )
    .unwrap()
    .unwrap();
    assert_eq!(dom.id, "domain-app");
    assert_eq!(dom.version.as_deref(), Some("2"));
    assert_eq!(dom.requires_domains, vec!["domain-base"]);
}

#[test]
fn ecosystem_workspace_detects_rust_python_domain_pin_skew_and_blast_radius() {
    let tmp = TempDir::new("multi-ecosystem");
    let ws = tmp.path();

    // 1. core-lib (<name>/trunk layout) with 2 git commits + baseline rollup.
    let core = ws.join("core-lib").join("trunk");
    fs::create_dir_all(core.join("src")).unwrap();
    init_git_repo(&core, "https://github.com/example/core-lib.git");
    fs::write(
        core.join("Cargo.toml"),
        "[package]\nname = \"core-lib\"\nversion = \"0.1.0\"\nedition = \"2024\"\n",
    )
    .unwrap();
    fs::write(core.join("src/lib.rs"), "pub fn version() -> u32 { 1 }\n").unwrap();
    let old_core_sha = commit_all(&core, "initial core-lib");

    fs::write(core.join("src/lib.rs"), "pub fn version() -> u32 { 2 }\n").unwrap();
    fs::write(
        core.join("semantic-profile.json"),
        r#"{"schema_version": 1, "budgets": {"max_scc_count": 0}}"#,
    )
    .unwrap();
    fs::write(
        core.join("semantic-baseline.json"),
        r#"{
  "schema_version": 1,
  "repo_label": "core-lib",
  "commit": "deadbeef",
  "summary": {
    "prod_loc": 420,
    "scc_count": 0,
    "top_hotspot_score": 88.5,
    "bypass_count": 1,
    "smeared_write_count": 0,
    "blanket_suppressions": 0
  },
  "files": [
    {"path": "src/lib.rs", "role": "production", "hotspot_score": 88.5},
    {"path": "tests/t.rs", "role": "test", "hotspot_score": 999.0}
  ]
}"#,
    )
    .unwrap();
    let head_core_sha = commit_all(&core, "bump core-lib to v2");
    assert_ne!(old_core_sha, head_core_sha);

    // 2. mid-service (<name>/trunk layout) pinning OLD core-lib SHA in Cargo.toml + Cargo.lock.
    let mid = ws.join("mid-service").join("trunk");
    fs::create_dir_all(mid.join("src")).unwrap();
    init_git_repo(&mid, "https://github.com/example/mid-service.git");
    fs::write(
        mid.join("Cargo.toml"),
        format!(
            "[package]\nname = \"mid-service\"\nversion = \"0.1.0\"\nedition = \"2024\"\n\n[dependencies]\ncore-lib = {{ git = \"https://github.com/example/core-lib\", rev = \"{old_core_sha}\" }}\n"
        ),
    )
    .unwrap();
    fs::write(
        mid.join("Cargo.lock"),
        format!(
            "version = 4\n\n[[package]]\nname = \"core-lib\"\nversion = \"0.1.0\"\nsource = \"git+https://github.com/example/core-lib?rev={old_core_sha}#{old_core_sha}\"\n"
        ),
    )
    .unwrap();
    fs::write(mid.join("src/lib.rs"), "pub fn serve() {}\n").unwrap();
    let _mid_sha = commit_all(&mid, "initial mid-service");

    // 3. edge-app (direct <name>/ layout) with relative Cargo path dep on mid-service
    //    and up-to-date git pin on core-lib (NO pin skew on core-lib!).
    let app = ws.join("edge-app");
    fs::create_dir_all(app.join("src")).unwrap();
    fs::write(
        app.join("Cargo.toml"),
        "[package]\nname = \"edge-app\"\nversion = \"0.1.0\"\nedition = \"2024\"\n\n[dependencies]\nmid-service = { path = \"../mid-service/trunk\" }\ncore-lib = { git = \"https://github.com/example/core-lib.git\", branch = \"main\" }\n",
    )
    .unwrap();
    fs::write(
        app.join("Cargo.lock"),
        format!(
            "version = 4\n\n[[package]]\nname = \"core-lib\"\nversion = \"0.1.0\"\nsource = \"git+https://github.com/example/core-lib.git?branch=main#{head_core_sha}\"\n"
        ),
    )
    .unwrap();
    fs::write(app.join("src/main.rs"), "fn main() {}\n").unwrap();

    // 4. Python repos: py-core and py-client.
    let py_core = ws.join("py-core").join("trunk");
    fs::create_dir_all(&py_core).unwrap();
    fs::write(
        py_core.join("pyproject.toml"),
        "[project]\nname = \"py_core\"\nversion = \"1.0.0\"\n",
    )
    .unwrap();

    let py_client = ws.join("py-client").join("trunk");
    fs::create_dir_all(&py_client).unwrap();
    fs::write(
        py_client.join("pyproject.toml"),
        "[project]\nname = \"py-client\"\nversion = \"1.0.0\"\ndependencies = [\"py-core>=1.0\"]\n",
    )
    .unwrap();

    // 5. Domain repos: domain-base and domain-app.
    let dom_base = ws.join("domain-base").join("trunk");
    fs::create_dir_all(&dom_base).unwrap();
    fs::write(
        dom_base.join("domain.json"),
        r#"{"id": "research-core", "version": "1"}"#,
    )
    .unwrap();

    let dom_app = ws.join("domain-app").join("trunk");
    fs::create_dir_all(&dom_app).unwrap();
    fs::write(
        dom_app.join("domain.json"),
        r#"{"id": "builder-domain", "version": "1", "requires_domains": ["research-core"]}"#,
    )
    .unwrap();

    let out_path = tmp.path().join("ecosystem-out.json");
    let code = cli::run([
        "semantic-profiler",
        "ecosystem",
        "--workspace-root",
        ws.to_str().unwrap(),
        "--impact",
        "core-lib",
        "--fail-on-cycle",
        "--output",
        out_path.to_str().unwrap(),
    ])
    .expect("ecosystem CLI run");
    assert_eq!(code, 0, "acyclic workspace must exit 0 under --fail-on-cycle");

    let raw_json = fs::read_to_string(&out_path).unwrap();
    let graph: EcosystemGraph = serde_json::from_str(&raw_json).unwrap();
    assert_eq!(graph.format, ECOSYSTEM_GRAPH_FORMAT);
    assert_eq!(graph.summary.repo_count, 7);
    assert_eq!(graph.summary.scc_count, 0);
    assert_eq!(graph.summary.pin_skew_count, 1);
    assert_eq!(graph.summary.rust_repo_count, 3);
    assert_eq!(graph.summary.python_repo_count, 2);
    assert_eq!(graph.summary.domain_repo_count, 2);
    assert_eq!(graph.summary.repos_with_profile, 1);
    assert_eq!(graph.summary.repos_with_baseline, 1);

    // Check core-lib node metadata and semantic health rollup.
    let core_node = graph.nodes.iter().find(|n| n.id == "core-lib").unwrap();
    assert_eq!(core_node.relative_path, "core-lib/trunk");
    assert_eq!(core_node.git_head.as_deref(), Some(head_core_sha.as_str()));
    assert_eq!(core_node.git_branch.as_deref(), Some("main"));
    assert_eq!(core_node.fan_in, 2);
    assert_eq!(core_node.fan_out, 0);
    assert_eq!(
        core_node.transitive_dependents,
        vec!["edge-app".to_string(), "mid-service".to_string()]
    );
    let health = core_node.semantic_health.as_ref().unwrap();
    assert_eq!(health.source, "baseline");
    assert_eq!(health.prod_loc, 420);
    assert_eq!(health.top_hotspot_path.as_deref(), Some("src/lib.rs"));
    assert_eq!(health.bypass_count, 1);

    // Check pin_skew entry: mid-service pinned old_core_sha while core-lib HEAD is head_core_sha.
    assert_eq!(graph.pin_skew.len(), 1);
    let skew = &graph.pin_skew[0];
    assert_eq!(skew.from_repo, "mid-service");
    assert_eq!(skew.to_repo, "core-lib");
    assert_eq!(skew.resolved_sha, old_core_sha);
    assert_eq!(skew.target_head_sha, head_core_sha);
    assert_eq!(skew.skew_source, "both");

    // Check edge types across all three ecosystems.
    assert!(
        graph
            .edges
            .iter()
            .any(|e| e.from == "edge-app" && e.to == "mid-service" && e.kind == "cargo_path")
    );
    assert!(graph.edges.iter().any(|e| {
        e.from == "edge-app" && e.to == "core-lib" && e.kind == "cargo_git" && !e.pin_skew
    }));
    assert!(
        graph
            .edges
            .iter()
            .any(|e| e.from == "py-client" && e.to == "py-core" && e.kind == "python_dep")
    );
    assert!(
        graph
            .edges
            .iter()
            .any(|e| e.from == "domain-app" && e.to == "domain-base" && e.kind == "domain_requires")
    );

    // Check impact report for core-lib.
    let impact = graph.impact.as_ref().unwrap();
    assert_eq!(impact.target_repo, "core-lib");
    assert_eq!(impact.direct_dependents, vec!["edge-app", "mid-service"]);
    assert_eq!(impact.transitive_dependent_count, 2);

    // Determinism: a second scan must serialize byte-for-byte identically.
    let second = scan_ecosystem(&EcosystemScanOptions {
        workspace_root: Some(ws.to_path_buf()),
        roots: Vec::new(),
        scan_repos: false,
        impact_target: Some("core-lib".to_string()),
    })
    .unwrap();
    assert_eq!(
        serde_json::to_string_pretty(&second).unwrap() + "\n",
        raw_json
    );
}

#[test]
fn ecosystem_detects_repo_cycles_and_exits_2_with_fail_on_cycle() {
    let tmp = TempDir::new("cycle");
    let ws = tmp.path();

    for (name, req) in [
        ("cycle-a", "dom-b"),
        ("cycle-b", "dom-c"),
        ("cycle-c", "dom-a"),
        ("leaf-d", "dom-a"),
    ] {
        let dir = ws.join(name);
        fs::create_dir_all(&dir).unwrap();
        let dom_id = match name {
            "cycle-a" => "dom-a",
            "cycle-b" => "dom-b",
            "cycle-c" => "dom-c",
            _ => "dom-d",
        };
        fs::write(
            dir.join("domain.json"),
            format!(r#"{{"id": "{dom_id}", "requires_domains": ["{req}"]}}"#),
        )
        .unwrap();
    }

    let out_path = tmp.path().join("cycle-graph.json");
    let code = cli::run([
        "semantic-profiler",
        "ecosystem",
        "--workspace-root",
        ws.to_str().unwrap(),
        "--impact",
        "cycle-b",
        "--fail-on-cycle",
        "--output",
        out_path.to_str().unwrap(),
    ])
    .expect("cycle CLI run");
    assert_eq!(code, 2, "cycles must return exit code 2 under --fail-on-cycle");

    let graph: EcosystemGraph =
        serde_json::from_str(&fs::read_to_string(&out_path).unwrap()).unwrap();
    assert_eq!(graph.sccs.len(), 1);
    assert_eq!(graph.sccs[0].id, "scc-1");
    assert_eq!(graph.sccs[0].repos, vec!["cycle-a", "cycle-b", "cycle-c"]);
    assert_eq!(graph.sccs[0].edge_count, 3);

    let leaf = graph.nodes.iter().find(|n| n.id == "leaf-d").unwrap();
    assert_eq!(leaf.scc_id, None);
    assert_eq!(leaf.fan_in, 0);
    assert_eq!(leaf.fan_out, 1);

    let impact = graph.impact.as_ref().unwrap();
    assert_eq!(impact.target_repo, "cycle-b");
    assert_eq!(impact.scc_members, vec!["cycle-a", "cycle-c"]);
    assert_eq!(
        impact.transitive_dependents,
        vec!["cycle-a", "cycle-c", "leaf-d"]
    );
}

#[test]
fn ecosystem_roots_mode_and_live_scan_repos_flag_work() {
    let tmp = TempDir::new("roots-live");
    let r1 = tmp.path().join("alpha");
    let r2 = tmp.path().join("beta");
    fs::create_dir_all(r1.join("src")).unwrap();
    fs::create_dir_all(r2.join("src")).unwrap();

    fs::write(
        r1.join("Cargo.toml"),
        "[package]\nname = \"alpha\"\nversion = \"0.1.0\"\nedition = \"2024\"\n",
    )
    .unwrap();
    fs::write(r1.join("src/lib.rs"), "pub fn ping() -> u32 { 7 }\n").unwrap();

    fs::write(
        r2.join("Cargo.toml"),
        "[package]\nname = \"beta\"\nversion = \"0.1.0\"\nedition = \"2024\"\n\n[dependencies]\nalpha = { path = \"../alpha\" }\n",
    )
    .unwrap();
    fs::write(r2.join("src/lib.rs"), "pub fn pong() -> u32 { 8 }\n").unwrap();

    let out_path = tmp.path().join("roots.json");
    let code = cli::run([
        "semantic-profiler",
        "ecosystem",
        "--roots",
        r1.to_str().unwrap(),
        r2.to_str().unwrap(),
        "--scan-repos",
        "--output",
        out_path.to_str().unwrap(),
    ])
    .expect("roots CLI run");
    assert_eq!(code, 0);

    let graph: EcosystemGraph =
        serde_json::from_str(&fs::read_to_string(&out_path).unwrap()).unwrap();
    assert_eq!(graph.discovery_mode, "roots");
    assert_eq!(graph.summary.repo_count, 2);
    assert_eq!(graph.summary.edge_count, 1);

    let alpha = graph.nodes.iter().find(|n| n.id == "alpha").unwrap();
    let health = alpha.semantic_health.as_ref().expect("live scan health");
    assert_eq!(health.source, "live_scan");
    assert!(health.prod_loc >= 1);

    // Unknown --impact target must fail cleanly.
    let err = cli::run([
        "semantic-profiler",
        "ecosystem",
        "--roots",
        r1.to_str().unwrap(),
        "--impact",
        "does-not-exist",
    ])
    .expect_err("unknown impact target should fail");
    assert!(err.contains("does-not-exist"));
}

#[test]
fn ecosystem_skips_symlinks_and_reparse_points_and_refuses_symlink_output() {
    let tmp = TempDir::new("symlink-safety");
    let ws = tmp.path().join("ws");
    let external = tmp.path().join("external-repo");
    fs::create_dir_all(ws.join("real-repo")).unwrap();
    fs::create_dir_all(&external).unwrap();

    fs::write(
        ws.join("real-repo").join("domain.json"),
        r#"{"id": "real-dom"}"#,
    )
    .unwrap();
    fs::write(
        external.join("domain.json"),
        r#"{"id": "external-dom", "requires_domains": ["real-dom"]}"#,
    )
    .unwrap();

    let link_dir = ws.join("linked-repo");
    let link_created = create_dir_link(&external, &link_dir);
    assert!(link_created, "test helper must create directory link/junction");

    let graph = scan_ecosystem(&EcosystemScanOptions {
        workspace_root: Some(ws.clone()),
        roots: Vec::new(),
        scan_repos: false,
        impact_target: None,
    })
    .unwrap();

    assert_eq!(graph.summary.repo_count, 1);
    assert_eq!(graph.nodes[0].id, "real-repo");
    assert!(
        graph
            .skipped
            .iter()
            .any(|s| s.path == "linked-repo" && s.reason.contains("symlink or reparse point"))
    );

    // Output writer must also refuse writing inside a symlink/junction directory
    // or a non-existent subdirectory beneath a symlink/junction ancestor.
    let bad_out = link_dir.join("escape.json");
    let err = cli::run([
        "semantic-profiler",
        "ecosystem",
        "--workspace-root",
        ws.to_str().unwrap(),
        "--output",
        bad_out.to_str().unwrap(),
    ])
    .expect_err("must refuse writing into symlink/junction directory");
    assert!(err.contains("symlink or reparse point"));
    assert!(!external.join("escape.json").exists());

    let nested_bad_out = link_dir.join("new-sub").join("deep").join("escape.json");
    let err_nested = cli::run([
        "semantic-profiler",
        "ecosystem",
        "--workspace-root",
        ws.to_str().unwrap(),
        "--output",
        nested_bad_out.to_str().unwrap(),
    ])
    .expect_err("must refuse writing beneath a symlink/junction ancestor");
    assert!(err_nested.contains("symlink or reparse point"));
    assert!(!external.join("new-sub").exists());

    // Explicit --roots <symlink> and trailing-slash --workspace-root <symlink>/ must fail closed.
    let err_root = cli::run([
        "semantic-profiler",
        "ecosystem",
        "--roots",
        link_dir.to_str().unwrap(),
    ])
    .expect_err("explicit --roots symlink must fail closed");
    assert!(err_root.contains("symlink or reparse point"));

    let link_with_trailing_sep = format!("{}/", link_dir.display());
    let err_ws = cli::run([
        "semantic-profiler",
        "ecosystem",
        "--workspace-root",
        &link_with_trailing_sep,
    ])
    .expect_err("workspace-root symlink with trailing slash must fail closed");
    assert!(err_ws.contains("symlink or reparse point"));
}

#[test]
fn crw_regressions_urls_multiline_toml_pep508_and_poetry_subtables() {
    // 1. Case-insensitive credential stripping, :22 SSH port stripping, and .GIT suffix.
    assert_eq!(
        normalize_git_url(concat!("HTTPS://user:secret_token", "@", "GitHub.com/Org/Repo.GIT")),
        "github.com/org/repo"
    );
    assert_eq!(
        normalize_git_url(concat!("SSH://git", "@", "github.com:22/Org/Repo.GIT/")),
        "github.com/org/repo"
    );
    assert_eq!(
        normalize_git_url(concat!(
            "GIT+HTTPS://token",
            "@",
            "github.com/Org/Repo.git?branch=main#deadbeef"
        )),
        "github.com/org/repo"
    );

    // 2. Multiline TOML strings ("""...""" and '''...''') must not corrupt sections/delimiters.
    let cargo = parse_cargo_toml(
        r#"
[package]
name = "real-crate"
version = "0.1.0"
description = """
# not a comment
[dependencies]
phantom = { git = "https://github.com/example/phantom" }
unbalanced = [ {
"""
readme = '''
[dependencies]
phantom2 = { path = "../phantom2" }
'''

[dependencies]
actual-dep = { git = "https://github.com/example/actual-dep", rev = "abcdef1234567" }
"#,
    );
    assert_eq!(cargo.package_name.as_deref(), Some("real-crate"));
    assert_eq!(cargo.dependencies.len(), 1);
    assert_eq!(cargo.dependencies[0].package_name, "actual-dep");

    // 3. PEP 508 @feature/foo (branch with slash) and Poetry subtables + path deps.
    let ssh_url = concat!("ssh://git", "@", "github.com/example/ssh-pkg.git");
    let py_manifest = format!(
        r#"
[project]
name = "py-consumer"
dependencies = [
    "slash-pkg @ git+https://github.com/example/slash-pkg.git@feature/foo#egg=slash-pkg",
    "ssh-pkg @ git+{ssh_url}@release/v2",
]

[tool.poetry.dependencies.local-lib]
path = "../local-lib"

[tool.poetry.group.dev.dependencies.git-helper]
git = "https://github.com/example/git-helper.git"
rev = "1234567890abcdef"
"#
    );
    let py = parse_pyproject_toml(&py_manifest);
    let slash_dep = py
        .dependencies
        .iter()
        .find(|d| d.normalized_name == "slash-pkg")
        .expect("slash-pkg");
    assert_eq!(
        slash_dep.git_url.as_deref(),
        Some("https://github.com/example/slash-pkg.git")
    );
    assert_eq!(slash_dep.git_rev.as_deref(), Some("feature/foo"));

    let ssh_dep = py
        .dependencies
        .iter()
        .find(|d| d.normalized_name == "ssh-pkg")
        .expect("ssh-pkg");
    assert_eq!(ssh_dep.git_url.as_deref(), Some(ssh_url));
    assert_eq!(ssh_dep.git_rev.as_deref(), Some("release/v2"));

    let local_lib = py
        .dependencies
        .iter()
        .find(|d| d.normalized_name == "local-lib")
        .expect("local-lib");
    assert_eq!(local_lib.path.as_deref(), Some("../local-lib"));

    let git_helper = py
        .dependencies
        .iter()
        .find(|d| d.normalized_name == "git-helper")
        .expect("git-helper");
    assert!(git_helper.is_optional);
    assert_eq!(git_helper.git_rev.as_deref(), Some("1234567890abcdef"));
}

#[test]
fn crw_regressions_var_exclude_third_party_collision_dual_path_git_and_py_skew() {
    let tmp = TempDir::new("crw-regressions");
    let ws = tmp.path();

    // 1. Local git repo `shared-lib` with remote github.com/myorg/shared-lib and 2 commits.
    let shared = ws.join("shared-lib");
    fs::create_dir_all(shared.join("src")).unwrap();
    init_git_repo(&shared, "https://github.com/myorg/shared-lib.git");
    fs::write(
        shared.join("Cargo.toml"),
        "[package]\nname = \"shared-lib\"\nversion = \"0.1.0\"\nedition = \"2024\"\n",
    )
    .unwrap();
    fs::write(shared.join("src/lib.rs"), "pub fn v() -> u32 { 1 }\n").unwrap();
    let old_shared_sha = commit_all(&shared, "v1");
    fs::write(shared.join("src/lib.rs"), "pub fn v() -> u32 { 2 }\n").unwrap();
    let head_shared_sha = commit_all(&shared, "v2");

    // 2. Local Python git repo `py-base` with 2 commits.
    let py_base = ws.join("py-base");
    fs::create_dir_all(&py_base).unwrap();
    init_git_repo(&py_base, "https://github.com/myorg/py-base.git");
    fs::write(
        py_base.join("pyproject.toml"),
        "[project]\nname = \"py-base\"\nversion = \"0.1.0\"\n",
    )
    .unwrap();
    let old_py_sha = commit_all(&py_base, "py v1");
    fs::write(
        py_base.join("pyproject.toml"),
        "[project]\nname = \"py-base\"\nversion = \"0.2.0\"\n",
    )
    .unwrap();
    let head_py_sha = commit_all(&py_base, "py v2");

    // 3. Consumer repo testing:
    //    - var/ and VAR/ ignored subdirs + [workspace] exclude pruning (must NOT emit phantom edges!)
    //    - third-party github.com/thirdparty/shared-lib must NOT collide with myorg/shared-lib!
    //    - dual path + git Cargo dep on myorg/shared-lib emits BOTH cargo_path and cargo_git + pin_skew!
    //    - pyproject.toml git dep on py-base pinned to old_py_sha emits skew_source == "pyproject_toml"!
    //    - pyproject.toml git dep pointing to a third-party URL with same name as a Rust crate
    //      must NOT fall back to index.by_rust_crate!
    let consumer = ws.join("consumer");
    fs::create_dir_all(consumer.join("src")).unwrap();
    fs::create_dir_all(consumer.join("var/evidence/snap")).unwrap();
    fs::create_dir_all(consumer.join("VAR/cache")).unwrap();
    fs::create_dir_all(consumer.join("excluded-sub")).unwrap();

    fs::write(
        consumer.join("Cargo.toml"),
        format!(
            "[package]\nname = \"consumer\"\nversion = \"0.1.0\"\nedition = \"2024\"\n\n[workspace]\nexclude = [\"excluded-sub\"]\n\n[dependencies]\nshared-lib = {{ path = \"../shared-lib\", git = \"https://github.com/myorg/shared-lib\", rev = \"{old_shared_sha}\" }}\nthirdparty-lib = {{ package = \"shared-lib\", git = \"https://github.com/thirdparty/shared-lib\", rev = \"1111111111111111111111111111111111111111\" }}\n"
        ),
    )
    .unwrap();
    fs::write(consumer.join("src/lib.rs"), "pub fn run() {}\n").unwrap();

    // Phantom manifests inside var/, VAR/, and workspace-excluded dir must be pruned!
    fs::write(
        consumer.join("var/evidence/snap/Cargo.toml"),
        "[package]\nname = \"phantom-var\"\nversion = \"0.1.0\"\n[dependencies]\nshared-lib = { git = \"https://github.com/myorg/shared-lib\", rev = \"0000000000000000000000000000000000000000\" }\n",
    )
    .unwrap();
    fs::write(
        consumer.join("VAR/cache/Cargo.toml"),
        "[package]\nname = \"phantom-upper-var\"\nversion = \"0.1.0\"\n",
    )
    .unwrap();
    fs::write(
        consumer.join("excluded-sub/Cargo.toml"),
        "[package]\nname = \"phantom-excluded\"\nversion = \"0.1.0\"\n[dependencies]\nshared-lib = { git = \"https://github.com/myorg/shared-lib\", rev = \"0000000000000000000000000000000000000000\" }\n",
    )
    .unwrap();

    fs::write(
        consumer.join("pyproject.toml"),
        format!(
            "[project]\nname = \"consumer-py\"\nversion = \"0.1.0\"\ndependencies = [\n  \"py-base @ git+https://github.com/myorg/py-base.git@{old_py_sha}\",\n  \"shared-lib @ git+https://github.com/other/unrelated.git@aaaaaaa\",\n]\n"
        ),
    )
    .unwrap();

    let graph = scan_ecosystem(&EcosystemScanOptions {
        workspace_root: Some(ws.to_path_buf()),
        roots: Vec::new(),
        scan_repos: false,
        impact_target: None,
    })
    .unwrap();

    let consumer_node = graph.nodes.iter().find(|n| n.id == "consumer").unwrap();
    assert!(
        !consumer_node
            .packages
            .iter()
            .any(|p| p.name.starts_with("phantom-")),
        "var/, VAR/, and [workspace] exclude manifests must be pruned: {:?}",
        consumer_node.packages
    );

    // Dual path + git dep on shared-lib emits BOTH cargo_path and cargo_git, and NO thirdparty edge!
    let rust_edges: Vec<_> = graph
        .edges
        .iter()
        .filter(|e| e.from == "consumer" && e.ecosystem == "rust")
        .collect();
    assert_eq!(
        rust_edges.len(),
        2,
        "expected exactly cargo_path + cargo_git (no thirdparty or phantom edges): {rust_edges:?}"
    );
    assert!(rust_edges.iter().any(|e| e.kind == "cargo_path" && e.to == "shared-lib"));
    assert!(
        rust_edges
            .iter()
            .any(|e| e.kind == "cargo_git" && e.to == "shared-lib" && e.pin_skew)
    );

    // Python edge resolves ONLY py-base (NOT shared-lib Rust crate!) and reports skew_source == "pyproject_toml".
    let py_edges: Vec<_> = graph
        .edges
        .iter()
        .filter(|e| e.from == "consumer" && e.ecosystem == "python")
        .collect();
    assert_eq!(py_edges.len(), 1, "expected only py-base edge: {py_edges:?}");
    assert_eq!(py_edges[0].to, "py-base");
    assert!(py_edges[0].pin_skew);

    let py_skew = graph
        .pin_skew
        .iter()
        .find(|s| s.to_repo == "py-base")
        .expect("py-base pin skew");
    assert_eq!(py_skew.skew_source, "pyproject_toml");
    assert_eq!(py_skew.resolved_sha, old_py_sha);
    assert_eq!(py_skew.target_head_sha, head_py_sha);

    let rust_skew = graph
        .pin_skew
        .iter()
        .find(|s| s.to_repo == "shared-lib")
        .expect("shared-lib pin skew");
    assert_eq!(rust_skew.skew_source, "cargo_toml");
    assert_eq!(rust_skew.resolved_sha, old_shared_sha);
    assert_eq!(rust_skew.target_head_sha, head_shared_sha);
}

fn create_dir_link(target: &Path, link: &Path) -> bool {
    #[cfg(unix)]
    {
        std::os::unix::fs::symlink(target, link).is_ok()
    }
    #[cfg(windows)]
    {
        // Use NTFS directory junction (reparse point) which requires no elevation.
        let mut cmd = Command::new("cmd");
        cmd.args([
            "/C",
            "mklink",
            "/J",
            link.to_str().unwrap(),
            target.to_str().unwrap(),
        ])
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .creation_flags(CREATE_NO_WINDOW);
        cmd.status().is_ok_and(|s| s.success())
    }
}
