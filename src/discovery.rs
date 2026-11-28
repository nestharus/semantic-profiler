//! Bounded repository source discovery, safe file reading, language detection,
//! and production vs. test/eval role separation.

use crate::model::{FileRole, Language, SkippedFile};
use crate::profile_config::RepoProfile;
pub use crate::safe_io::{is_reparse_or_symlink, read_file_bounded};
use std::fs;
use std::path::{Path, PathBuf};

pub const MAX_SOURCE_BYTES: u64 = 4 * 1024 * 1024;
pub const MAX_WALK_DEPTH: usize = 32;
pub const MAX_DISCOVERED_FILES: usize = 50_000;

const SKIPPED_DIRS: &[&str] = &[
    ".git",
    "target",
    "node_modules",
    ".venv",
    "venv",
    "__pycache__",
    ".pytest_cache",
    ".mypy_cache",
    ".ruff_cache",
    ".scratch",
    "dist",
    "build",
    "vendor",
    ".cargo",
];

#[derive(Debug, Clone)]
pub struct DiscoveredFile {
    pub rel_path: String,
    pub abs_path: PathBuf,
    pub language: Language,
    pub role: FileRole,
}

#[derive(Debug, Default)]
pub struct DiscoveryResult {
    pub files: Vec<DiscoveredFile>,
    pub skipped: Vec<SkippedFile>,
}

pub fn discover_files(
    repo_root: &Path,
    profile: &RepoProfile,
    include_evals: bool,
) -> Result<DiscoveryResult, String> {
    discover_files_with_limit(repo_root, profile, include_evals, MAX_DISCOVERED_FILES)
}

pub fn discover_files_with_limit(
    repo_root: &Path,
    profile: &RepoProfile,
    include_evals: bool,
    max_files: usize,
) -> Result<DiscoveryResult, String> {
    if !repo_root.is_dir() {
        return Err(format!(
            "scan target is not a directory: {}",
            repo_root.display()
        ));
    }
    let mut result = DiscoveryResult::default();
    let mut ctx = WalkCtx {
        root: repo_root,
        profile,
        include_evals,
        max_files,
        cap_recorded: false,
        out: &mut result,
    };
    ctx.walk_dir(repo_root, 0);
    result.files.sort_by(|a, b| a.rel_path.cmp(&b.rel_path));
    result.skipped.sort_by(|a, b| a.path.cmp(&b.path));
    Ok(result)
}

struct WalkCtx<'a> {
    root: &'a Path,
    profile: &'a RepoProfile,
    include_evals: bool,
    max_files: usize,
    cap_recorded: bool,
    out: &'a mut DiscoveryResult,
}

impl WalkCtx<'_> {
    fn walk_dir(&mut self, dir: &Path, depth: usize) {
        if self.out.files.len() >= self.max_files {
            if !self.cap_recorded {
                self.cap_recorded = true;
                self.out.skipped.push(SkippedFile {
                    path: rel_posix(self.root, dir),
                    reason: format!("max discovered files cap ({}) reached", self.max_files),
                });
            }
            return;
        }

        if depth > MAX_WALK_DEPTH {
            self.out.skipped.push(SkippedFile {
                path: rel_posix(self.root, dir),
                reason: "max directory depth exceeded".to_string(),
            });
            return;
        }

        let entries = match fs::read_dir(dir) {
            Ok(e) => e,
            Err(e) => {
                self.out.skipped.push(SkippedFile {
                    path: rel_posix(self.root, dir),
                    reason: format!("directory read error: {e}"),
                });
                return;
            }
        };

        let mut paths: Vec<PathBuf> = Vec::new();
        for entry in entries {
            match entry {
                Ok(e) => paths.push(e.path()),
                Err(e) => self.out.skipped.push(SkippedFile {
                    path: rel_posix(self.root, dir),
                    reason: format!("directory entry error: {e}"),
                }),
            }
        }
        paths.sort();

        for path in paths {
            if self.out.files.len() >= self.max_files {
                if !self.cap_recorded {
                    self.cap_recorded = true;
                    self.out.skipped.push(SkippedFile {
                        path: rel_posix(self.root, &path),
                        reason: format!("max discovered files cap ({}) reached", self.max_files),
                    });
                }
                return;
            }

            let meta = match fs::symlink_metadata(&path) {
                Ok(m) => m,
                Err(e) => {
                    self.out.skipped.push(SkippedFile {
                        path: rel_posix(self.root, &path),
                        reason: format!("stat error: {e}"),
                    });
                    continue;
                }
            };

            if is_reparse_or_symlink(&meta) {
                self.out.skipped.push(SkippedFile {
                    path: rel_posix(self.root, &path),
                    reason: "symlink or reparse point skipped".to_string(),
                });
                continue;
            }

            let name = path.file_name().and_then(|s| s.to_str()).unwrap_or("");
            let lower_name = name.to_ascii_lowercase();
            let rel = rel_posix(self.root, &path);

            if meta.is_dir() {
                if SKIPPED_DIRS.contains(&name) || path.join("pyvenv.cfg").is_file() {
                    continue;
                }
                if !self.include_evals && (lower_name == "evals" || lower_name == "eval") {
                    continue;
                }
                if self.profile.is_ignored(&rel) {
                    continue;
                }
                self.walk_dir(&path, depth + 1);
                continue;
            }

            if !meta.is_file() || self.profile.is_ignored(&rel) {
                continue;
            }

            let Some(language) = detect_language(&path) else {
                continue;
            };

            if meta.len() > MAX_SOURCE_BYTES {
                self.out.skipped.push(SkippedFile {
                    path: rel,
                    reason: format!("file exceeds {} bytes", MAX_SOURCE_BYTES),
                });
                continue;
            }

            let role = classify_role(&rel, self.profile);
            self.out.files.push(DiscoveredFile {
                rel_path: rel,
                abs_path: path,
                language,
                role,
            });
        }
    }
}

pub fn detect_language(path: &Path) -> Option<Language> {
    let ext = path.extension().and_then(|s| s.to_str())?.to_ascii_lowercase();
    match ext.as_str() {
        "rs" => Some(Language::Rust),
        "py" => Some(Language::Python),
        "ts" | "tsx" => Some(Language::TypeScript),
        "js" | "jsx" | "mjs" | "cjs" => Some(Language::JavaScript),
        "go" => Some(Language::Go),
        "sh" | "bash" => Some(Language::Shell),
        _ => None,
    }
}

pub fn classify_role(rel_path: &str, profile: &RepoProfile) -> FileRole {
    let lower = rel_path.to_ascii_lowercase();
    let segments: Vec<&str> = lower.split('/').collect();
    if segments.iter().any(|s| *s == "evals" || *s == "eval") {
        return FileRole::Eval;
    }
    if profile.is_profile_test(rel_path) {
        return FileRole::Test;
    }
    if segments.iter().any(|s| {
        matches!(
            *s,
            "tests" | "test" | "__tests__" | "unit_tests" | "fixtures" | "benches"
        )
    }) {
        return FileRole::Test;
    }
    let file_name = segments.last().copied().unwrap_or("");
    if file_name.starts_with("test_")
        || file_name.ends_with("_test.rs")
        || file_name.ends_with("_tests.rs")
        || file_name.ends_with("_test.py")
        || file_name.ends_with("_test.go")
        || file_name.ends_with(".test.ts")
        || file_name.ends_with(".spec.ts")
        || file_name.ends_with(".test.js")
        || file_name.ends_with(".spec.js")
    {
        return FileRole::Test;
    }
    FileRole::Production
}

fn rel_posix(root: &Path, path: &Path) -> String {
    path.strip_prefix(root)
        .unwrap_or(path)
        .to_string_lossy()
        .replace('\\', "/")
}
