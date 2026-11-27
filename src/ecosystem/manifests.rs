//! Dependency-free manifest and lockfile parsers for Rust (`Cargo.toml`, `Cargo.lock`),
//! Python (`pyproject.toml`), Domain packages (`domain.json`), and semantic baseline rollups.

use crate::ecosystem::model::SemanticHealthRollup;
use crate::safe_io::{is_reparse_or_symlink, read_file_bounded};
use serde::Deserialize;
use std::collections::BTreeMap;
use std::fs;
use std::path::Path;

pub const MAX_MANIFEST_BYTES: u64 = 16 * 1024 * 1024;
pub const MAX_BASELINE_BYTES: u64 = 64 * 1024 * 1024;

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ParsedCargoManifest {
    pub package_name: Option<String>,
    pub package_version: Option<String>,
    pub workspace_members: Vec<String>,
    pub workspace_exclude: Vec<String>,
    pub dependencies: Vec<CargoDepSpec>,
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct CargoDepSpec {
    pub alias: String,
    pub package_name: String,
    pub section: String,
    pub git: Option<String>,
    pub rev: Option<String>,
    pub branch: Option<String>,
    pub tag: Option<String>,
    pub path: Option<String>,
    pub version: Option<String>,
    pub workspace: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CargoLockGitEntry {
    pub name: String,
    pub version: Option<String>,
    pub git_url: String,
    pub normalized_git_url: String,
    pub query_ref: Option<String>,
    pub resolved_sha: String,
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ParsedPyproject {
    pub package_name: Option<String>,
    pub package_version: Option<String>,
    pub dependencies: Vec<PythonDepSpec>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PythonDepSpec {
    pub name: String,
    pub normalized_name: String,
    pub section: String,
    pub is_optional: bool,
    pub raw_spec: String,
    pub git_url: Option<String>,
    pub git_rev: Option<String>,
    pub path: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ParsedDomainManifest {
    pub id: String,
    pub version: Option<String>,
    pub requires_domains: Vec<String>,
}

#[derive(Debug, Deserialize)]
struct BaselinePartial {
    #[serde(default)]
    commit: Option<String>,
    summary: BaselineSummaryPartial,
    #[serde(default)]
    files: Vec<BaselineFilePartial>,
}

#[derive(Debug, Deserialize)]
struct BaselineSummaryPartial {
    #[serde(default)]
    prod_loc: usize,
    #[serde(default)]
    scc_count: usize,
    #[serde(default)]
    top_hotspot_score: f64,
    #[serde(default)]
    bypass_count: usize,
    #[serde(default)]
    smeared_write_count: usize,
    #[serde(default)]
    blanket_suppressions: usize,
}

#[derive(Debug, Deserialize)]
struct BaselineFilePartial {
    path: String,
    #[serde(default)]
    role: String,
    #[serde(default)]
    hotspot_score: f64,
}

#[derive(Debug, Deserialize)]
struct RawDomainManifest {
    #[serde(default)]
    id: Option<String>,
    #[serde(default)]
    version: Option<serde_json::Value>,
    #[serde(default)]
    requires_domains: Vec<String>,
}

/// Read a UTF-8 file safely (rejecting symlinks/reparse points and oversized files).
pub fn read_utf8_safe(path: &Path, max_bytes: u64) -> Result<String, String> {
    let meta = fs::symlink_metadata(path).map_err(|e| format!("stat error: {e}"))?;
    if is_reparse_or_symlink(&meta) {
        return Err("symlink or reparse point skipped".to_string());
    }
    if !meta.is_file() {
        return Err("not a regular file".to_string());
    }
    let bytes = read_file_bounded(path, max_bytes)?;
    let raw = String::from_utf8(bytes).map_err(|_| "non-UTF-8 file skipped".to_string())?;
    Ok(raw.strip_prefix('\u{feff}').unwrap_or(&raw).to_string())
}

pub fn parse_baseline_rollup(text: &str) -> Result<SemanticHealthRollup, String> {
    let parsed: BaselinePartial =
        serde_json::from_str(text).map_err(|e| format!("invalid baseline JSON: {e}"))?;
    let top_hotspot_path = parsed
        .files
        .iter()
        .filter(|f| f.role.is_empty() || f.role == "production")
        .max_by(|a, b| {
            a.hotspot_score
                .total_cmp(&b.hotspot_score)
                .then_with(|| b.path.cmp(&a.path))
        })
        .map(|f| f.path.clone());

    Ok(SemanticHealthRollup {
        source: "baseline".to_string(),
        commit: parsed.commit,
        prod_loc: parsed.summary.prod_loc,
        scc_count: parsed.summary.scc_count,
        top_hotspot_score: parsed.summary.top_hotspot_score,
        top_hotspot_path,
        bypass_count: parsed.summary.bypass_count,
        smeared_write_count: parsed.summary.smeared_write_count,
        blanket_suppressions: parsed.summary.blanket_suppressions,
    })
}

pub fn parse_domain_json(text: &str) -> Result<Option<ParsedDomainManifest>, String> {
    let raw: RawDomainManifest =
        serde_json::from_str(text).map_err(|e| format!("invalid domain.json: {e}"))?;
    let Some(id) = raw.id.map(|s| s.trim().to_string()).filter(|s| !s.is_empty()) else {
        return Ok(None);
    };
    let version = raw.version.and_then(|v| match v {
        serde_json::Value::String(s) => Some(s),
        serde_json::Value::Number(n) => Some(n.to_string()),
        _ => None,
    });
    let requires_domains = raw
        .requires_domains
        .into_iter()
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
        .collect();
    Ok(Some(ParsedDomainManifest {
        id,
        version,
        requires_domains,
    }))
}

pub fn parse_cargo_toml(text: &str) -> ParsedCargoManifest {
    let mut out = ParsedCargoManifest::default();
    let mut section = String::new();
    let mut subtable_deps: BTreeMap<(String, String), CargoDepSpec> = BTreeMap::new();

    for stmt in collect_toml_statements(text) {
        if let Some(header) = parse_table_header(&stmt) {
            section = header;
            continue;
        }
        let Some((key, val)) = split_toml_kv(&stmt) else {
            continue;
        };

        if section == "package" {
            match key.as_str() {
                "name" => out.package_name = parse_toml_string(&val),
                "version" => out.package_version = parse_toml_string(&val),
                _ => {}
            }
            continue;
        }
        if section == "workspace" {
            match key.as_str() {
                "members" => out.workspace_members = parse_toml_string_array(&val),
                "exclude" => out.workspace_exclude = parse_toml_string_array(&val),
                _ => {}
            }
            continue;
        }

        if let Some((dep_section, sub_alias)) = classify_cargo_dep_section(&section) {
            if let Some(alias) = sub_alias {
                let entry = subtable_deps
                    .entry((dep_section.clone(), alias.clone()))
                    .or_insert_with(|| new_cargo_dep(&alias, &dep_section));
                apply_cargo_dep_field(entry, &key, &val);
            } else if let Some((alias, field)) = split_dotted_key(&key) {
                let entry = subtable_deps
                    .entry((dep_section.clone(), alias.clone()))
                    .or_insert_with(|| new_cargo_dep(&alias, &dep_section));
                apply_cargo_dep_field(entry, &field, &val);
            } else {
                let alias = unquote_toml_key(&key);
                let mut dep = new_cargo_dep(&alias, &dep_section);
                if val.starts_with('{') && val.ends_with('}') {
                    for (ik, iv) in parse_inline_table(&val) {
                        apply_cargo_dep_field(&mut dep, &ik, &iv);
                    }
                } else if let Some(ver) = parse_toml_string(&val) {
                    dep.version = Some(ver);
                }
                out.dependencies.push(dep);
            }
        }
    }

    for (_, dep) in subtable_deps {
        out.dependencies.push(dep);
    }
    out
}

fn new_cargo_dep(alias: &str, section: &str) -> CargoDepSpec {
    CargoDepSpec {
        alias: alias.to_string(),
        package_name: alias.to_string(),
        section: section.to_string(),
        ..CargoDepSpec::default()
    }
}

fn apply_cargo_dep_field(dep: &mut CargoDepSpec, key: &str, val: &str) {
    match unquote_toml_key(key).as_str() {
        "package" => {
            if let Some(s) = parse_toml_string(val) {
                dep.package_name = s;
            }
        }
        "git" => dep.git = parse_toml_string(val),
        "rev" => dep.rev = parse_toml_string(val),
        "branch" => dep.branch = parse_toml_string(val),
        "tag" => dep.tag = parse_toml_string(val),
        "path" => dep.path = parse_toml_string(val),
        "version" => dep.version = parse_toml_string(val),
        "workspace" => dep.workspace = val.trim() == "true",
        _ => {}
    }
}

fn classify_cargo_dep_section(section: &str) -> Option<(String, Option<String>)> {
    let parts = split_toml_path(section);
    if parts.is_empty() {
        return None;
    }
    let first = parts[0].as_str();
    if matches!(first, "dependencies" | "dev-dependencies" | "build-dependencies") {
        if parts.len() == 1 {
            return Some((first.to_string(), None));
        }
        if parts.len() == 2 {
            return Some((first.to_string(), Some(parts[1].clone())));
        }
        return None;
    }
    if first == "workspace" && parts.get(1).map(String::as_str) == Some("dependencies") {
        if parts.len() == 2 {
            return Some(("workspace.dependencies".to_string(), None));
        }
        if parts.len() == 3 {
            return Some(("workspace.dependencies".to_string(), Some(parts[2].clone())));
        }
        return None;
    }
    if first == "target" && parts.len() >= 3 {
        let kind = parts[2].as_str();
        if matches!(kind, "dependencies" | "dev-dependencies" | "build-dependencies") {
            if parts.len() == 3 {
                return Some((kind.to_string(), None));
            }
            if parts.len() == 4 {
                return Some((kind.to_string(), Some(parts[3].clone())));
            }
        }
    }
    None
}

pub fn parse_cargo_lock(text: &str) -> Vec<CargoLockGitEntry> {
    let mut entries = Vec::new();
    let mut in_pkg = false;
    let mut name: Option<String> = None;
    let mut version: Option<String> = None;
    let mut source: Option<String> = None;

    let flush = |entries: &mut Vec<CargoLockGitEntry>,
                 name: &mut Option<String>,
                 version: &mut Option<String>,
                 source: &mut Option<String>| {
        if let (Some(pkg_name), Some(src)) = (name.take(), source.take())
            && let Some(rest) = src.strip_prefix("git+")
            && let Some((url_and_query, sha)) = rest.rsplit_once('#')
        {
            let sha = sha.trim();
            if !sha.is_empty() {
                let (git_url, query_ref) = match url_and_query.split_once('?') {
                    Some((u, q)) => (u.to_string(), Some(q.to_string())),
                    None => (url_and_query.to_string(), None),
                };
                let normalized_git_url = normalize_git_url(&git_url);
                entries.push(CargoLockGitEntry {
                    name: pkg_name,
                    version: version.take(),
                    git_url,
                    normalized_git_url,
                    query_ref,
                    resolved_sha: sha.to_ascii_lowercase(),
                });
                return;
            }
        }
        *name = None;
        *version = None;
        *source = None;
    };

    for raw_line in text.lines() {
        let line = strip_toml_comment(raw_line).trim();
        if line.is_empty() {
            continue;
        }
        if line == "[[package]]" {
            if in_pkg {
                flush(&mut entries, &mut name, &mut version, &mut source);
            }
            in_pkg = true;
            continue;
        }
        if line.starts_with('[') {
            if in_pkg {
                flush(&mut entries, &mut name, &mut version, &mut source);
            }
            in_pkg = false;
            continue;
        }
        if !in_pkg {
            continue;
        }
        if let Some((k, v)) = split_toml_kv(line) {
            match k.as_str() {
                "name" => name = parse_toml_string(&v),
                "version" => version = parse_toml_string(&v),
                "source" => source = parse_toml_string(&v),
                _ => {}
            }
        }
    }
    if in_pkg {
        flush(&mut entries, &mut name, &mut version, &mut source);
    }
    entries
}

pub fn parse_pyproject_toml(text: &str) -> ParsedPyproject {
    let mut out = ParsedPyproject::default();
    let mut section = String::new();
    let mut poetry_name: Option<String> = None;
    let mut poetry_version: Option<String> = None;
    let mut poetry_subtable_deps: BTreeMap<(String, String), PythonDepSpec> = BTreeMap::new();

    for stmt in collect_toml_statements(text) {
        if let Some(header) = parse_table_header(&stmt) {
            section = header;
            continue;
        }
        let Some((key, val)) = split_toml_kv(&stmt) else {
            continue;
        };

        if section == "project" {
            match key.as_str() {
                "name" => out.package_name = parse_toml_string(&val),
                "version" => out.package_version = parse_toml_string(&val),
                "dependencies" => {
                    for raw_spec in parse_toml_string_array(&val) {
                        if let Some(spec) =
                            parse_pep508_dep(&raw_spec, "project.dependencies", false)
                        {
                            out.dependencies.push(spec);
                        }
                    }
                }
                _ => {}
            }
        } else if section == "project.optional-dependencies" {
            let group = unquote_toml_key(&key);
            let sec = format!("project.optional-dependencies.{group}");
            for raw_spec in parse_toml_string_array(&val) {
                if let Some(spec) = parse_pep508_dep(&raw_spec, &sec, true) {
                    out.dependencies.push(spec);
                }
            }
        } else if section == "dependency-groups" {
            let group = unquote_toml_key(&key);
            let sec = format!("dependency-groups.{group}");
            for raw_spec in parse_toml_string_array(&val) {
                if let Some(spec) = parse_pep508_dep(&raw_spec, &sec, true) {
                    out.dependencies.push(spec);
                }
            }
        } else if section == "tool.poetry" {
            match key.as_str() {
                "name" => poetry_name = parse_toml_string(&val),
                "version" => poetry_version = parse_toml_string(&val),
                _ => {}
            }
        } else if let Some((dep_section, is_optional, sub_pkg)) =
            classify_poetry_dep_section(&section)
        {
            if let Some(pkg) = sub_pkg {
                if pkg.eq_ignore_ascii_case("python") {
                    continue;
                }
                let entry = poetry_subtable_deps
                    .entry((dep_section.clone(), pkg.clone()))
                    .or_insert_with(|| PythonDepSpec {
                        normalized_name: normalize_python_name(&pkg),
                        name: pkg,
                        section: dep_section,
                        is_optional,
                        raw_spec: String::new(),
                        git_url: None,
                        git_rev: None,
                        path: None,
                    });
                apply_poetry_dep_field(entry, &key, &val);
            } else if let Some((pkg, field)) = split_dotted_key(&key) {
                if pkg.eq_ignore_ascii_case("python") {
                    continue;
                }
                let entry = poetry_subtable_deps
                    .entry((dep_section.clone(), pkg.clone()))
                    .or_insert_with(|| PythonDepSpec {
                        normalized_name: normalize_python_name(&pkg),
                        name: pkg,
                        section: dep_section,
                        is_optional,
                        raw_spec: String::new(),
                        git_url: None,
                        git_rev: None,
                        path: None,
                    });
                apply_poetry_dep_field(entry, &field, &val);
            } else {
                let dep_name = unquote_toml_key(&key);
                if dep_name.eq_ignore_ascii_case("python") {
                    continue;
                }
                let mut spec = PythonDepSpec {
                    normalized_name: normalize_python_name(&dep_name),
                    name: dep_name,
                    section: dep_section,
                    is_optional,
                    raw_spec: val.clone(),
                    git_url: None,
                    git_rev: None,
                    path: None,
                };
                if val.starts_with('{') && val.ends_with('}') {
                    for (ik, iv) in parse_inline_table(&val) {
                        apply_poetry_dep_field(&mut spec, &ik, &iv);
                    }
                }
                out.dependencies.push(spec);
            }
        }
    }

    for (_, dep) in poetry_subtable_deps {
        out.dependencies.push(dep);
    }
    if out.package_name.is_none() {
        out.package_name = poetry_name;
    }
    if out.package_version.is_none() {
        out.package_version = poetry_version;
    }
    out
}

fn classify_poetry_dep_section(section: &str) -> Option<(String, bool, Option<String>)> {
    let parts = split_toml_path(section);
    if parts.len() < 3 || parts[0] != "tool" || parts[1] != "poetry" {
        return None;
    }
    match parts[2].as_str() {
        "dependencies" => match parts.len() {
            3 => Some(("tool.poetry.dependencies".to_string(), false, None)),
            4 => Some((
                "tool.poetry.dependencies".to_string(),
                false,
                Some(parts[3].clone()),
            )),
            _ => None,
        },
        "dev-dependencies" => match parts.len() {
            3 => Some(("tool.poetry.dev-dependencies".to_string(), true, None)),
            4 => Some((
                "tool.poetry.dev-dependencies".to_string(),
                true,
                Some(parts[3].clone()),
            )),
            _ => None,
        },
        "group" if parts.len() >= 5 && parts[4] == "dependencies" => {
            let base = format!("tool.poetry.group.{}.dependencies", parts[3]);
            match parts.len() {
                5 => Some((base, true, None)),
                6 => Some((base, true, Some(parts[5].clone()))),
                _ => None,
            }
        }
        _ => None,
    }
}

fn apply_poetry_dep_field(spec: &mut PythonDepSpec, key: &str, val: &str) {
    match unquote_toml_key(key).as_str() {
        "git" => spec.git_url = parse_toml_string(val),
        "rev" => spec.git_rev = parse_toml_string(val),
        "path" => spec.path = parse_toml_string(val),
        "version" => {
            if spec.raw_spec.is_empty()
                && let Some(v) = parse_toml_string(val)
            {
                spec.raw_spec = v;
            }
        }
        _ => {}
    }
}

pub fn normalize_python_name(name: &str) -> String {
    let mut out = String::with_capacity(name.len());
    let mut last_dash = false;
    for ch in name.trim().chars() {
        if ch == '-' || ch == '_' || ch == '.' {
            if !last_dash && !out.is_empty() {
                out.push('-');
                last_dash = true;
            }
        } else {
            out.push(ch.to_ascii_lowercase());
            last_dash = false;
        }
    }
    while out.ends_with('-') {
        out.pop();
    }
    out
}

pub fn parse_pep508_dep(raw: &str, section: &str, is_optional: bool) -> Option<PythonDepSpec> {
    let trimmed = raw.trim();
    if trimmed.is_empty() {
        return None;
    }
    let before_marker = trimmed.split(';').next().unwrap_or(trimmed).trim();
    let (head, direct_url) = match before_marker.split_once('@') {
        Some((lhs, rhs)) => (lhs.trim(), Some(rhs.trim())),
        None => (before_marker, None),
    };

    let name_len = head
        .bytes()
        .take_while(|b| b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_' | b'.'))
        .count();
    if name_len == 0 {
        return None;
    }
    let name = head[..name_len].to_string();
    let normalized_name = normalize_python_name(&name);
    if normalized_name.is_empty() {
        return None;
    }

    let (git_url, git_rev) = match direct_url {
        Some(url) if url.len() >= 4 && url[..4].eq_ignore_ascii_case("git+") => {
            let stripped = &url[4..];
            let without_frag = stripped.split('#').next().unwrap_or(stripped);
            split_pep508_git_ref(without_frag)
        }
        _ => (None, None),
    };

    Some(PythonDepSpec {
        name,
        normalized_name,
        section: section.to_string(),
        is_optional,
        raw_spec: trimmed.to_string(),
        git_url,
        git_rev,
        path: None,
    })
}

fn split_pep508_git_ref(url_no_frag: &str) -> (Option<String>, Option<String>) {
    let after_scheme = url_no_frag.find("://").map(|i| i + 3).unwrap_or(0);
    let path_start = url_no_frag[after_scheme..]
        .find('/')
        .map(|rel| after_scheme + rel);
    if let Some(slash_idx) = path_start
        && let Some(rel_at) = url_no_frag[slash_idx..].find('@')
    {
        let at_idx = slash_idx + rel_at;
        let base_url = &url_no_frag[..at_idx];
        let rev = &url_no_frag[(at_idx + 1)..];
        if !rev.is_empty() {
            return (Some(base_url.to_string()), Some(rev.to_string()));
        }
        return (Some(base_url.to_string()), None);
    }
    (Some(url_no_frag.to_string()), None)
}

/// Normalize a git remote or dependency URL to a lowercase `host/owner/repo` slug
/// without credentials, scheme, default SSH `:22` port, or `.git` suffix.
pub fn normalize_git_url(raw: &str) -> String {
    let mut s = raw.trim().replace('\\', "/").to_ascii_lowercase();
    if let Some((before_frag, _)) = s.split_once('#') {
        s = before_frag.to_string();
    }
    if let Some((before_query, _)) = s.split_once('?') {
        s = before_query.to_string();
    }
    if let Some(rest) = s.strip_prefix("git+") {
        s = rest.to_string();
    }
    for scheme in ["https://", "http://", "ssh://", "git://", "file://"] {
        if let Some(rest) = s.strip_prefix(scheme) {
            s = rest.to_string();
            break;
        }
    }
    // Strip user/token authority prefix like `git@` or `user:token@` before the first `/`.
    if let Some(at_pos) = s.find('@') {
        let slash_pos = s.find('/').unwrap_or(s.len());
        if at_pos < slash_pos {
            s = s[(at_pos + 1)..].to_string();
        }
    }
    // Handle default SSH `:22` port and SCP-style `github.com:owner/repo`.
    if let Some(colon_pos) = s.find(':') {
        let slash_pos = s.find('/').unwrap_or(s.len());
        if colon_pos < slash_pos {
            let host = &s[..colon_pos];
            let rest = &s[(colon_pos + 1)..];
            let digits_len = rest.bytes().take_while(|b| b.is_ascii_digit()).count();
            if digits_len > 0 && rest.as_bytes().get(digits_len) == Some(&b'/') {
                if &rest[..digits_len] == "22" {
                    s = format!("{host}{}", &rest[digits_len..]);
                }
            } else {
                s = format!("{host}/{rest}");
            }
        }
    }
    while s.ends_with('/') {
        s.pop();
    }
    if let Some(stripped) = s.strip_suffix(".git") {
        s = stripped.to_string();
    }
    while s.ends_with('/') {
        s.pop();
    }
    s
}

pub fn git_url_repo_tail(normalized_url: &str) -> Option<&str> {
    normalized_url
        .rsplit('/')
        .next()
        .filter(|seg| !seg.is_empty())
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum MultilineString {
    None,
    Basic,
    Literal,
}

fn collect_toml_statements(text: &str) -> Vec<String> {
    let mut statements = Vec::new();
    let mut current = String::new();
    let mut bracket_depth: i32 = 0;
    let mut brace_depth: i32 = 0;
    let mut ml_state = MultilineString::None;

    for raw_line in text.lines() {
        let clean = scan_toml_line(raw_line, &mut ml_state, &mut bracket_depth, &mut brace_depth);
        let trimmed = clean.trim();
        if trimmed.is_empty() {
            continue;
        }
        if !current.is_empty() {
            current.push(' ');
        }
        current.push_str(trimmed);
        if ml_state == MultilineString::None && bracket_depth <= 0 && brace_depth <= 0 {
            bracket_depth = 0;
            brace_depth = 0;
            statements.push(std::mem::take(&mut current));
        }
    }
    if !current.trim().is_empty() {
        statements.push(current);
    }
    statements
}

fn scan_toml_line(
    line: &str,
    ml_state: &mut MultilineString,
    bracket_depth: &mut i32,
    brace_depth: &mut i32,
) -> String {
    let bytes = line.as_bytes();
    let len = bytes.len();
    let mut i = 0usize;
    let mut in_double = false;
    let mut in_single = false;
    let mut escaped = false;
    let mut out = String::with_capacity(len);

    while i < len {
        match *ml_state {
            MultilineString::Basic => {
                if escaped {
                    let ch = line[i..].chars().next().unwrap();
                    out.push(ch);
                    i += ch.len_utf8();
                    escaped = false;
                    continue;
                }
                if bytes[i] == b'\\' {
                    out.push('\\');
                    i += 1;
                    escaped = true;
                    continue;
                }
                if line[i..].starts_with("\"\"\"") {
                    let mut q = 0usize;
                    while i + q < len && bytes[i + q] == b'"' {
                        q += 1;
                    }
                    out.push_str(&line[i..(i + q)]);
                    i += q;
                    *ml_state = MultilineString::None;
                    continue;
                }
                let ch = line[i..].chars().next().unwrap();
                out.push(ch);
                i += ch.len_utf8();
                continue;
            }
            MultilineString::Literal => {
                if line[i..].starts_with("'''") {
                    let mut q = 0usize;
                    while i + q < len && bytes[i + q] == b'\'' {
                        q += 1;
                    }
                    out.push_str(&line[i..(i + q)]);
                    i += q;
                    *ml_state = MultilineString::None;
                    continue;
                }
                let ch = line[i..].chars().next().unwrap();
                out.push(ch);
                i += ch.len_utf8();
                continue;
            }
            MultilineString::None => {}
        }

        if in_double {
            let ch = line[i..].chars().next().unwrap();
            out.push(ch);
            i += ch.len_utf8();
            if escaped {
                escaped = false;
            } else if ch == '\\' {
                escaped = true;
            } else if ch == '"' {
                in_double = false;
            }
            continue;
        }
        if in_single {
            let ch = line[i..].chars().next().unwrap();
            out.push(ch);
            i += ch.len_utf8();
            if ch == '\'' {
                in_single = false;
            }
            continue;
        }

        if line[i..].starts_with("\"\"\"") {
            out.push_str("\"\"\"");
            i += 3;
            *ml_state = MultilineString::Basic;
            continue;
        }
        if line[i..].starts_with("'''") {
            out.push_str("'''");
            i += 3;
            *ml_state = MultilineString::Literal;
            continue;
        }

        let ch = line[i..].chars().next().unwrap();
        if ch == '#' {
            break;
        }
        match ch {
            '"' => in_double = true,
            '\'' => in_single = true,
            '[' => *bracket_depth += 1,
            ']' => *bracket_depth -= 1,
            '{' => *brace_depth += 1,
            '}' => *brace_depth -= 1,
            _ => {}
        }
        out.push(ch);
        i += ch.len_utf8();
    }
    out
}

fn strip_toml_comment(line: &str) -> &str {
    let mut in_double = false;
    let mut in_single = false;
    let mut escaped = false;
    for (idx, ch) in line.char_indices() {
        if in_double {
            if escaped {
                escaped = false;
            } else if ch == '\\' {
                escaped = true;
            } else if ch == '"' {
                in_double = false;
            }
            continue;
        }
        if in_single {
            if ch == '\'' {
                in_single = false;
            }
            continue;
        }
        match ch {
            '"' => in_double = true,
            '\'' => in_single = true,
            '#' => return &line[..idx],
            _ => {}
        }
    }
    line
}

fn parse_table_header(stmt: &str) -> Option<String> {
    let trimmed = stmt.trim();
    if trimmed.starts_with("[[") && trimmed.ends_with("]]") && trimmed.len() >= 4 {
        return Some(trimmed[2..(trimmed.len() - 2)].trim().to_string());
    }
    if trimmed.starts_with('[') && trimmed.ends_with(']') && trimmed.len() >= 2 {
        return Some(trimmed[1..(trimmed.len() - 1)].trim().to_string());
    }
    None
}

fn split_toml_kv(stmt: &str) -> Option<(String, String)> {
    let mut in_double = false;
    let mut in_single = false;
    let mut escaped = false;
    for (idx, ch) in stmt.char_indices() {
        if in_double {
            if escaped {
                escaped = false;
            } else if ch == '\\' {
                escaped = true;
            } else if ch == '"' {
                in_double = false;
            }
            continue;
        }
        if in_single {
            if ch == '\'' {
                in_single = false;
            }
            continue;
        }
        match ch {
            '"' => in_double = true,
            '\'' => in_single = true,
            '=' => {
                let k = stmt[..idx].trim();
                let v = stmt[(idx + 1)..].trim();
                if !k.is_empty() {
                    return Some((k.to_string(), v.to_string()));
                }
                return None;
            }
            _ => {}
        }
    }
    None
}

fn split_toml_path(path: &str) -> Vec<String> {
    let mut parts = Vec::new();
    let mut cur = String::new();
    let mut in_double = false;
    let mut in_single = false;
    let mut escaped = false;
    for ch in path.chars() {
        if in_double {
            if escaped {
                cur.push(ch);
                escaped = false;
            } else if ch == '\\' {
                escaped = true;
            } else if ch == '"' {
                in_double = false;
            } else {
                cur.push(ch);
            }
            continue;
        }
        if in_single {
            if ch == '\'' {
                in_single = false;
            } else {
                cur.push(ch);
            }
            continue;
        }
        match ch {
            '"' => in_double = true,
            '\'' => in_single = true,
            '.' => {
                let seg = cur.trim().to_string();
                if !seg.is_empty() {
                    parts.push(seg);
                }
                cur.clear();
            }
            _ => cur.push(ch),
        }
    }
    let seg = cur.trim().to_string();
    if !seg.is_empty() {
        parts.push(seg);
    }
    parts
}

fn split_dotted_key(key: &str) -> Option<(String, String)> {
    let parts = split_toml_path(key);
    if parts.len() == 2 {
        Some((parts[0].clone(), parts[1].clone()))
    } else {
        None
    }
}

fn unquote_toml_key(key: &str) -> String {
    let trimmed = key.trim();
    parse_toml_string(trimmed).unwrap_or_else(|| trimmed.to_string())
}

fn parse_toml_string(raw: &str) -> Option<String> {
    let t = raw.trim();
    if t.len() >= 2 && t.starts_with('\'') && t.ends_with('\'') {
        return Some(t[1..(t.len() - 1)].to_string());
    }
    if t.len() >= 2 && t.starts_with('"') && t.ends_with('"') {
        let inner = &t[1..(t.len() - 1)];
        let mut out = String::with_capacity(inner.len());
        let mut chars = inner.chars();
        while let Some(ch) = chars.next() {
            if ch == '\\' {
                match chars.next() {
                    Some('n') => out.push('\n'),
                    Some('r') => out.push('\r'),
                    Some('t') => out.push('\t'),
                    Some('\\') => out.push('\\'),
                    Some('"') => out.push('"'),
                    Some(other) => out.push(other),
                    None => break,
                }
            } else {
                out.push(ch);
            }
        }
        return Some(out);
    }
    None
}

fn parse_toml_string_array(raw: &str) -> Vec<String> {
    let t = raw.trim();
    if !(t.starts_with('[') && t.ends_with(']')) {
        return Vec::new();
    }
    let inner = &t[1..(t.len() - 1)];
    split_top_level_commas(inner)
        .into_iter()
        .filter_map(|item| parse_toml_string(&item))
        .collect()
}

fn parse_inline_table(raw: &str) -> Vec<(String, String)> {
    let t = raw.trim();
    if !(t.starts_with('{') && t.ends_with('}')) {
        return Vec::new();
    }
    let inner = &t[1..(t.len() - 1)];
    split_top_level_commas(inner)
        .into_iter()
        .filter_map(|item| split_toml_kv(&item))
        .collect()
}

fn split_top_level_commas(s: &str) -> Vec<String> {
    let mut items = Vec::new();
    let mut cur = String::new();
    let mut in_double = false;
    let mut in_single = false;
    let mut escaped = false;
    let mut depth = 0i32;

    for ch in s.chars() {
        if in_double {
            cur.push(ch);
            if escaped {
                escaped = false;
            } else if ch == '\\' {
                escaped = true;
            } else if ch == '"' {
                in_double = false;
            }
            continue;
        }
        if in_single {
            cur.push(ch);
            if ch == '\'' {
                in_single = false;
            }
            continue;
        }
        match ch {
            '"' => {
                in_double = true;
                cur.push(ch);
            }
            '\'' => {
                in_single = true;
                cur.push(ch);
            }
            '[' | '{' => {
                depth += 1;
                cur.push(ch);
            }
            ']' | '}' => {
                depth -= 1;
                cur.push(ch);
            }
            ',' if depth == 0 => {
                let item = cur.trim().to_string();
                if !item.is_empty() {
                    items.push(item);
                }
                cur.clear();
            }
            _ => cur.push(ch),
        }
    }
    let tail = cur.trim().to_string();
    if !tail.is_empty() {
        items.push(tail);
    }
    items
}
