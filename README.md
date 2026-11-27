# semantic-profiler

`semantic-profiler` is a fast, deterministic static AST, git-churn, and relationship-topology linter and profiler for multi-language codebases (Rust, Python, TypeScript/JavaScript, Go, and Shell).

It measures where engineers and automated reviewers spend comprehension and safe-modification budget across production code—catching circular dependency clusters (Tarjan SCCs), architectural layer/facade bypasses, smeared persistent write ownership, high blast-radius nexus hubs, blanket lint suppressions, and phantom git co-change coupling—while separating tests and dampening inert static lookup tables, flat exhaustive dispatchers, pure leaf utilities, and thin composition roots.

## 60-Second Quickstart

```bash
# 1. Build the release binary (Rust 1.89+)
cargo build --release --locked

# 2. Check any repository (auto-loads <repo>/semantic-profile.json if present)
cargo run --locked -- check .

# 3. Enforce budgets in CI with a checked-in profile and optional baseline snapshot
cargo run --locked -- check . --require-profile --base semantic-baseline.json
```

To bootstrap a repository:

1. Copy one of the starter profiles from [`examples/`](examples/) (for example [`examples/rust-service.semantic-profile.json`](examples/rust-service.semantic-profile.json)) to `semantic-profile.json` at the root of your repository.
2. Optionally capture a baseline snapshot for drift tracking:
   ```bash
   semantic-profiler scan . --output semantic-baseline.json
   ```
3. Run `semantic-profiler check . --require-profile --base semantic-baseline.json`.

## Subcommands

### `check` (Linter & CI Gate)

```text
semantic-profiler check <repo-path> [--profile <path>] [--base <baseline.json>] [--window <N>] [--top <K>] [--json] [--output <path>] [--emit-crw-packet <path>] [--emit-graph-edges <path> | --graph-edges <path>] [--include-evals] [--require-profile]
```

- Scans `<repo-path>`, auto-loading `<repo-path>/semantic-profile.json` unless `--profile <path>` overrides.
- Evaluates `budgets` from the loaded profile. If no profile or no budgets are configured, prints a clear warning and exits `0` unless `--require-profile` is passed (which fails when no profile file exists).
- When `--base <baseline.json>` is supplied, computes a longitudinal `SnapshotDelta` against the baseline.
- Emits a concise human-readable report by default, or structured JSON (`CheckReport`) with `--json`.
- Exit codes: `0` when all budgets pass, `2` when any budget violation occurs, `1` on CLI/runtime errors (invalid flags, unreadable baseline, or missing profile under `--require-profile`).

### `scan` (Full Snapshot & Artifact Export)

```text
semantic-profiler scan <repo-path> [--window <N>] [--top <K>] [--profile <path>] [--output <path>] [--jsonl <path>] [--emit-crw-packet <path>] [--emit-graph-edges <path> | --graph-edges <path>] [--include-evals]
```

- `--window <N>`: rolling `git log` commit window for churn and co-change coupling (default `100`; `0` skips git history).
- `--top <K>`: maximum hotspots, co-change pairs, and topology entries included in summaries and packets (default `15`).
- `--output <path>`: write the portable JSON snapshot to a file (defaults to stdout).
- `--jsonl <path>`: append one compact summary record for longitudinal time-series tracking.
- `--emit-crw-packet <path>`: write a compact Layer 2 CRW handoff packet JSON.
- `--emit-graph-edges <path>` (`--graph-edges <path>`): write typed graph edges (`imports`, `declares_mod`, `bypasses`, `in_scc`, `shares_write_target`, `phantom_cochanges`) and production node metadata.
- `--include-evals`: include `evals/` directories in the scan (excluded by default).

### `delta` (Snapshot-to-Snapshot Drift)

```text
semantic-profiler delta --base <base.json> --head <head.json> [--top <K>] [--output <path>] [--emit-crw-packet <path>] [--fail-on-budget]
```

- Computes per-file LOC, token, function length, nesting depth, suppression, and hotspot score deltas alongside topology deltas (`scc_count_delta`, `bypass_count_delta`, `smeared_write_count_delta`, `phantom_coupling_count_delta`).
- With `--fail-on-budget`, exits `2` when configured budgets in the head snapshot are exceeded.

### `ecosystem` (Cross-Repo Dependency, Pin-Skew, and Blast-Radius Graph)

```text
semantic-profiler ecosystem (--workspace-root <dir> | --roots <dir1> [<dir2> ...]) [--output <json_path>] [--impact <repo_name>] [--fail-on-cycle] [--scan-repos]
```

- Discovers repositories across `--workspace-root <dir>` (supporting both `<name>/` and `<name>/trunk` layouts) and/or explicit `--roots <dir1> <dir2> ...`, rejecting symlink/reparse points safely.
- Extracts per-repo git HEAD/branch/remote metadata, detected ecosystems (`rust`, `python`, `domain`), published crates/packages/domain IDs, and optional semantic-health rollups from `semantic-baseline.json` (or live AST scans when `--scan-repos` is passed).
- Resolves cross-repo dependencies from `Cargo.toml` (`[dependencies]`, `[dev-dependencies]`, `[build-dependencies]`, `[workspace.dependencies]` git & relative path refs) + `Cargo.lock` resolved commit SHAs, `pyproject.toml` (`[project].dependencies`, `optional-dependencies`, `dependency-groups`, Poetry tables), and `domain.json` (`requires_domains`).
- Detects repo-level dependency cycles via iterative Tarjan SCC (`--fail-on-cycle` exits `2` when any repo-level SCC exists), flags `pin_skew` when a pinned/locked SHA diverges from the target repository's actual git HEAD, and computes per-repo `fan_in`, `fan_out`, transitive dependents, and shortest-path `--impact <repo_name>` blast-radius reports.
- Emits deterministic canonical JSON (`format: "semantic-ecosystem-graph/1"`) to stdout or atomically to `--output <json_path>`.

## Configuration (`semantic-profile.json`)

Validate your repository's `semantic-profile.json` against the Draft 2020-12 JSON Schema in [`schemas/semantic-profile.schema.json`](schemas/semantic-profile.schema.json). Unknown fields are rejected strictly (`additionalProperties: false`).

```json
{
  "schema_version": 1,
  "domain_vocabulary": ["handler", "service", "storage"],
  "cohesive_data_globs": ["src/tables/*.rs"],
  "flat_dispatcher_globs": ["src/dispatch.rs"],
  "test_globs": ["tests/**", "**/*_test.rs"],
  "ignore_globs": ["generated/**"],
  "layers": [
    { "name": "api", "globs": ["src/cli.rs", "src/cli/**"] },
    { "name": "service", "globs": ["src/service.rs", "src/service/**"] },
    { "name": "storage", "globs": ["src/store.rs", "src/storage/**"] }
  ],
  "allowed_edges": [
    { "from": "api", "to": "service" },
    { "from": "service", "to": "storage" }
  ],
  "forbidden_bypasses": [
    { "from": "api", "to": "storage" }
  ],
  "budgets": {
    "max_hotspot_score": 450.0,
    "max_prod_fn_loc": 250,
    "max_blanket_suppressions": 0,
    "max_scc_count": 0,
    "max_bypass_count": 0,
    "max_smeared_write_count": 0
  }
}
```

See starter templates in [`examples/rust-service.semantic-profile.json`](examples/rust-service.semantic-profile.json) and [`examples/rust-workspace.semantic-profile.json`](examples/rust-workspace.semantic-profile.json).

### Relationship-Topology Signals

1. **Circular Dependency Clusters (`sccs`)**: exact iterative Tarjan strongly connected components (`|SCC| >= 2`) across production modules, with locked production LOC and estimated tokens.
2. **Layer / Facade Bypasses (`bypasses`)**: declared `layers`/`strata` + `allowed_edges`/`forbidden_bypasses` violations, shortcut triangles (`A -> B -> C` alongside direct `A -> C` into a non-leaf module), and cross-boundary reach-ins (`#[path = "..."]`, private `_module` imports, deep `internal`/`private`/`detail` imports), while exempting pure zero-fan-out leaf utilities, static data tables, and direct parent module indices.
3. **Smeared Write Ownership (`smeared_writes`)**: persistent filenames or storage key prefixes written by two or more distinct production modules (excluding test/eval files and ephemeral capture streams such as `stdout`, `stderr`, `stdout.txt`, `stderr.txt`, `stdout.bin`, `stderr.bin`, and `prompt.txt`).
4. **Spaghetti Nexus & Blast Radius (`top_nexus_nodes`)**: `nexus_score = fan_in * fan_out` plus reverse-reachable `transitive_dependents` and `transitive_dependent_tokens`.
5. **Phantom Coupling (`phantom_couplings`)**: production file pairs with `>= 2` git co-changes despite zero direct import edge (external Rust `mod foo;` declarations resolve directly to `foo.rs` or `foo/mod.rs` to eliminate false positives on `lib.rs` and `mod.rs`).

## GitHub Actions Usage

Use the bundled composite action (`action.yml`) in any repository's CI workflow:

```yaml
name: Semantic Profile Check

on: [push, pull_request]

jobs:
  semantic-check:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
        with:
          fetch-depth: 0

      - uses: dtolnay/rust-toolchain@stable

      - uses: nestharus/semantic-profiler@main
        with:
          path: .
          baseline: semantic-baseline.json
          require-profile: "true"
```

## Pre-Push Hook & Standalone Release Layout

For local pre-push enforcement, build a release image (`cargo build --release --locked`) and archive releases under `artifacts/<commit>/`:

- **Windows:** place `semantic-profiler.exe` beside the `semantic-profiler.cmd` and `semantic-profiler` (Git Bash) launchers on `PATH`, or run them directly from the repository checkout (both fall back to `target/release/semantic-profiler.exe`).
- **Linux / macOS:** install the compiled binary `target/release/semantic-profiler` directly onto a `PATH` directory (for example `~/.local/bin/semantic-profiler`), or invoke the repository's `./semantic-profiler` wrapper script which executes `target/release/semantic-profiler` without colliding with the wrapper filename.

Then add a lightweight `.git/hooks/pre-push` check:

```sh
#!/bin/sh
set -eu
semantic-profiler check . --require-profile
```

## Layer 2 CRW Handoff

Static scores and topology counts are challengeable Layer 1 signals, not automatic defect verdicts. Pass `--emit-crw-packet <path>` (with `check`, `scan`, or `delta`) to emit a compact `semantic-hotspot-and-drift-packet` JSON containing top hotspots, dampened counterexamples, blanket-suppression files, topology findings, and optional longitudinal drift for downstream Layer 2 semantic review. Pass `--emit-graph-edges <path>` to export typed nodes and edges for graph-index or context-discovery tools.

## Architecture

- `cli`: command-line parsing and subcommand dispatch (`check`, `scan`, `delta`, `ecosystem`).
- `ecosystem`: cross-repo manifest/lockfile parsing (`manifests`), portable ecosystem graph schemas (`model`), Tarjan SCC and blast-radius analysis (`topology`), and workspace discovery/pin-skew orchestration (`mod`).
- `profile_config`: `semantic-profile.json` loading, validation, stratum classification, and linear-time glob matching.
- `safe_io`: zero-fan-out leaf utility for symlink/reparse-point rejection and bounded file reads.
- `discovery`: bounded directory walk, language classification, and production vs. test/eval role separation.
- `rust_ast`: `syn` + `proc-macro2` Rust AST analyzer separating inline `#[cfg(test)]`, measuring per-function metrics, suppressions, internal `use` / external `mod` edges, reach-ins, write sinks, static tables, and flat dispatchers.
- `text_analyzer`: brace- and indentation-aware analyzer for Python, TypeScript/JavaScript, Go, Shell, and Rust parse fallback.
- `git_history`: bounded rolling-window churn and co-change extraction.
- `graph_topology`: package-scoped production import graph, Tarjan SCCs, bypass/reach-in detection, smeared write ownership, nexus blast-radius, phantom coupling, and portable graph-edge export.
- `scoring`: fan-in/fan-out resolution and dampened composite hotspot scoring.
- `delta`: longitudinal snapshot comparison and budget evaluation.
- `crw_packet`: Layer 2 Semantic Hotspot & Drift Packet emitter.
