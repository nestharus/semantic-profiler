//! Indentation- and brace-aware semantic analyzer for Python, TypeScript,
//! JavaScript, Go, Shell, and Rust parse-fallback files.

use crate::model::{
    FileClassification, FunctionMetrics, Language, ReachInSignal, SuppressionMetrics, WriteSinkHit,
};
use crate::python_scan::{scan_python_functions, scan_python_line_states};
use crate::rust_ast::{
    AnalyzedUnit, estimate_tokens, has_preceding_comment, is_private_ident,
    is_storage_receiver_name, is_valid_put_target, normalize_write_target,
};
use std::collections::BTreeSet;

const MAX_WRITE_SINKS_PER_FILE: usize = 128;
const MAX_REACH_INS_PER_FILE: usize = 128;

pub fn analyze_text_source(
    source: &str,
    language: Language,
    is_test_or_eval: bool,
    parse_fallback: bool,
) -> AnalyzedUnit {
    match language {
        Language::Python => analyze_python(source, is_test_or_eval, parse_fallback),
        Language::Rust
        | Language::TypeScript
        | Language::JavaScript
        | Language::Go
        | Language::Shell => {
            analyze_brace_or_shell(source, language, is_test_or_eval, parse_fallback)
        }
    }
}

fn analyze_python(source: &str, is_test_or_eval: bool, parse_fallback: bool) -> AnalyzedUnit {
    let lines: Vec<&str> = source.lines().collect();
    let line_states = scan_python_line_states(&lines);
    let total_loc = lines.len();
    let mut suppressions = SuppressionMetrics::default();
    let mut imports: BTreeSet<String> = BTreeSet::new();
    let mut import_paths: BTreeSet<String> = BTreeSet::new();
    let mut reach_ins: Vec<ReachInSignal> = Vec::new();
    let mut write_targets: Vec<WriteSinkHit> = Vec::new();
    let mut seen_writes: BTreeSet<(String, usize)> = BTreeSet::new();

    for (idx, line) in lines.iter().enumerate() {
        if line_states[idx].starts_in_string() {
            continue;
        }
        let trimmed = line.trim();
        let line_no = idx + 1;

        if let Some(rest) = trimmed.strip_prefix("from ")
            && let Some((module, imported_names)) = rest.split_once(" import ")
        {
            let raw_mod = module.trim();
            let leading_dots = raw_mod.chars().take_while(|&c| c == '.').count();
            let cleaned = &raw_mod[leading_dots..];
            let mod_segs: Vec<&str> = cleaned.split('.').filter(|s| !s.is_empty()).collect();
            let parent_hops: Vec<&str> = vec![".."; leading_dots.saturating_sub(1)];

            if !mod_segs.is_empty() {
                let mut full_segs = parent_hops.clone();
                full_segs.extend_from_slice(&mod_segs);
                let mut added_sub = false;
                for item in imported_names.split(',') {
                    let sym = item
                        .trim()
                        .trim_start_matches('(')
                        .trim_end_matches(')')
                        .split_whitespace()
                        .next()
                        .unwrap_or("");
                    if !sym.is_empty() && sym != "*" {
                        let mut with_sym = full_segs.clone();
                        with_sym.push(sym);
                        import_paths.insert(with_sym.join("/"));
                        added_sub = true;
                    }
                }
                if !added_sub {
                    import_paths.insert(full_segs.join("/"));
                }
                if let Some(last_seg) = mod_segs.last() {
                    imports.insert((*last_seg).to_string());
                }
                if mod_segs.len() > 1
                    && let Some(first_seg) = mod_segs.first()
                {
                    imports.insert((*first_seg).to_string());
                }
            } else {
                // `from . import foo, _bar` or `from .. import foo, _bar`
                for item in imported_names.split(',') {
                    let sym = item
                        .trim()
                        .trim_start_matches('(')
                        .trim_end_matches(')')
                        .split_whitespace()
                        .next()
                        .unwrap_or("");
                    if !sym.is_empty() {
                        imports.insert(sym.to_string());
                        let mut full_segs = parent_hops.clone();
                        full_segs.push(sym);
                        import_paths.insert(full_segs.join("/"));
                    }
                }
            }

            if !is_test_or_eval && reach_ins.len() < MAX_REACH_INS_PER_FILE {
                let mut flagged = false;
                if mod_segs.iter().any(|s| is_private_ident(s)) {
                    reach_ins.push(ReachInSignal {
                        kind: "python_private_import".to_string(),
                        target: cleaned.to_string(),
                        line: line_no,
                    });
                    flagged = true;
                } else if mod_segs.len() >= 2
                    && mod_segs
                        .iter()
                        .any(|s| matches!(*s, "internal" | "private" | "detail"))
                {
                    reach_ins.push(ReachInSignal {
                        kind: "python_deep_internal_import".to_string(),
                        target: cleaned.to_string(),
                        line: line_no,
                    });
                    flagged = true;
                }
                if !flagged {
                    for item in imported_names.split(',') {
                        let sym = item
                            .trim()
                            .trim_start_matches('(')
                            .trim_end_matches(')')
                            .split_whitespace()
                            .next()
                            .unwrap_or("");
                        if is_private_ident(sym) && reach_ins.len() < MAX_REACH_INS_PER_FILE {
                            let tgt = if cleaned.is_empty() {
                                sym.to_string()
                            } else {
                                format!("{cleaned}.{sym}")
                            };
                            reach_ins.push(ReachInSignal {
                                kind: "python_private_import".to_string(),
                                target: tgt,
                                line: line_no,
                            });
                            break;
                        }
                    }
                }
            }
        } else if let Some(rest) = trimmed.strip_prefix("import ") {
            for part in rest.split(',') {
                let full_mod = part.split_whitespace().next().unwrap_or("");
                let segs: Vec<&str> = full_mod.split('.').filter(|s| !s.is_empty()).collect();
                if !segs.is_empty() {
                    import_paths.insert(segs.join("/"));
                    if let Some(last) = segs.last() {
                        imports.insert((*last).to_string());
                    }
                    if let Some(first) = segs.first() {
                        imports.insert((*first).to_string());
                    }
                    if !is_test_or_eval && reach_ins.len() < MAX_REACH_INS_PER_FILE {
                        if segs.iter().any(|s| is_private_ident(s)) {
                            reach_ins.push(ReachInSignal {
                                kind: "python_private_import".to_string(),
                                target: full_mod.to_string(),
                                line: line_no,
                            });
                        } else if segs.len() >= 2
                            && segs
                                .iter()
                                .any(|s| matches!(*s, "internal" | "private" | "detail"))
                        {
                            reach_ins.push(ReachInSignal {
                                kind: "python_deep_internal_import".to_string(),
                                target: full_mod.to_string(),
                                line: line_no,
                            });
                        }
                    }
                }
            }
        }

        if !is_test_or_eval {
            scan_python_suppression(trimmed, &lines, line_no, &mut suppressions);
            if !trimmed.starts_with('#') {
                scan_python_write_sinks(trimmed, line_no, &mut write_targets, &mut seen_writes);
            }
        }
    }

    let functions = if is_test_or_eval {
        Vec::new()
    } else {
        scan_python_functions(&lines, &line_states)
    };

    let prod_loc = if is_test_or_eval { 0 } else { total_loc };
    let detected_classification = if is_test_or_eval {
        FileClassification::TestOrEval
    } else if functions.is_empty()
        && total_loc >= 60
        && suppressions.blanket == 0
        && looks_like_static_data(&lines)
    {
        FileClassification::StaticDataTable
    } else {
        FileClassification::Standard
    };

    AnalyzedUnit {
        total_loc,
        prod_loc,
        inline_test_loc: 0,
        est_tokens: estimate_tokens(source),
        functions,
        suppressions,
        internal_imports: imports.into_iter().collect(),
        import_paths: import_paths.into_iter().collect(),
        mod_decl_paths: Vec::new(),
        reach_ins,
        write_targets,
        detected_classification,
        parse_fallback,
    }
}

fn analyze_brace_or_shell(
    source: &str,
    language: Language,
    is_test_or_eval: bool,
    parse_fallback: bool,
) -> AnalyzedUnit {
    let lines: Vec<&str> = source.lines().collect();
    let total_loc = lines.len();
    let mut functions = Vec::new();
    let mut suppressions = SuppressionMetrics::default();
    let mut imports: BTreeSet<String> = BTreeSet::new();
    let mut import_paths: BTreeSet<String> = BTreeSet::new();
    let mut reach_ins: Vec<ReachInSignal> = Vec::new();
    let mut write_targets: Vec<WriteSinkHit> = Vec::new();
    let mut seen_writes: BTreeSet<(String, usize)> = BTreeSet::new();

    for (idx, line) in lines.iter().enumerate() {
        let trimmed = line.trim();
        let line_no = idx + 1;
        if !is_test_or_eval {
            scan_general_suppression(trimmed, language, &lines, line_no, &mut suppressions);
            if !trimmed.starts_with("//") && !(language == Language::Shell && trimmed.starts_with('#'))
            {
                scan_general_write_sinks(trimmed, language, line_no, &mut write_targets, &mut seen_writes);
            }
        }
        extract_general_import(
            trimmed,
            language,
            line_no,
            is_test_or_eval,
            &mut imports,
            &mut import_paths,
            &mut reach_ins,
        );
    }

    if !is_test_or_eval {
        let mut idx = 0usize;
        while idx < lines.len() {
            let trimmed = lines[idx].trim();
            if let Some((name, params)) = detect_brace_fn_header(trimmed, language) {
                let start_line = idx + 1;
                let mut brace_depth: i32 = 0;
                let mut seen_open = false;
                let mut max_nesting = 0usize;
                let mut end_idx = idx;

                for (j, cur_line) in lines.iter().enumerate().skip(idx) {
                    let (opens, closes) = count_structural_braces(cur_line, language);
                    if opens > 0 {
                        seen_open = true;
                    }
                    brace_depth += opens;
                    if brace_depth > 1 {
                        let nested = (brace_depth - 1) as usize;
                        if nested > max_nesting {
                            max_nesting = nested;
                        }
                    }
                    brace_depth -= closes;
                    end_idx = j;
                    if seen_open && brace_depth <= 0 {
                        break;
                    }
                }
                let end_line = end_idx + 1;
                functions.push(FunctionMetrics {
                    name,
                    start_line,
                    end_line,
                    loc: end_line.saturating_sub(start_line) + 1,
                    param_count: params,
                    max_nesting_depth: max_nesting,
                    is_flat_dispatcher: false,
                });
                idx = end_idx + 1;
                continue;
            }
            idx += 1;
        }
    }

    let prod_loc = if is_test_or_eval { 0 } else { total_loc };
    let detected_classification = if is_test_or_eval {
        FileClassification::TestOrEval
    } else if functions.is_empty()
        && total_loc >= 60
        && suppressions.blanket == 0
        && looks_like_static_data(&lines)
    {
        FileClassification::StaticDataTable
    } else {
        FileClassification::Standard
    };

    AnalyzedUnit {
        total_loc,
        prod_loc,
        inline_test_loc: 0,
        est_tokens: estimate_tokens(source),
        functions,
        suppressions,
        internal_imports: imports.into_iter().collect(),
        import_paths: import_paths.into_iter().collect(),
        mod_decl_paths: Vec::new(),
        reach_ins,
        write_targets,
        detected_classification,
        parse_fallback,
    }
}

fn record_write_hit(
    target: String,
    sink: &str,
    line: usize,
    out: &mut Vec<WriteSinkHit>,
    seen: &mut BTreeSet<(String, usize)>,
) {
    if out.len() >= MAX_WRITE_SINKS_PER_FILE {
        return;
    }
    if seen.insert((target.clone(), line)) {
        out.push(WriteSinkHit {
            target,
            sink: sink.to_string(),
            line,
        });
    }
}

fn scan_python_write_sinks(
    trimmed: &str,
    line: usize,
    out: &mut Vec<WriteSinkHit>,
    seen: &mut BTreeSet<(String, usize)>,
) {
    let code = strip_inline_comment(trimmed, Language::Python);
    let code = code.trim();
    if code.is_empty() {
        return;
    }

    // 1. `open(<target>, "w"|...)` or `open(<target>, mode="w")` bounded to the balanced `open(...)` call.
    if let Some(pos) = find_call_pos(code, "open(")
        && let Some(inside) = extract_balanced_paren_body(&code[pos + 5..])
    {
        let args = split_top_level_args(inside);
        let target = args
            .first()
            .and_then(|a| extract_quoted_literals(a).into_iter().last())
            .and_then(|s| normalize_write_target(&s));
        let positional_write = args
            .get(1)
            .and_then(|a| extract_first_literal_arg(a))
            .is_some_and(|m| is_python_write_mode(&m));
        let kw_write = args.iter().skip(1).any(|a| {
            let trimmed_arg = a.trim();
            if let Some(rest) = trimmed_arg.strip_prefix("mode") {
                let after = rest.trim_start();
                if let Some(val) = after.strip_prefix('=') {
                    return extract_first_literal_arg(val)
                        .is_some_and(|m| is_python_write_mode(&m));
                }
            }
            false
        });
        if (positional_write || kw_write)
            && let Some(norm) = target
        {
            record_write_hit(norm, "open(w)", line, out, seen);
        }
    }

    // 2. `.write_text(` or `.write_bytes(` restricted strictly to the immediate receiver expression.
    for method in [".write_text(", ".write_bytes("] {
        if let Some(pos) = code.find(method) {
            let receiver = extract_immediate_receiver(&code[..pos]);
            let lits = extract_quoted_literals(receiver);
            if let Some(last) = lits.last()
                && let Some(norm) = normalize_write_target(last)
            {
                record_write_hit(
                    norm,
                    method.trim_start_matches('.').trim_end_matches('('),
                    line,
                    out,
                    seen,
                );
            }
        }
    }

    // 3. Direct sink calls: `write_text("...", ...)`, `write_bytes("...", ...)`, `commit_tx("...", ...)`.
    for (needle, sink) in [
        ("write_text(", "write_text"),
        ("write_bytes(", "write_bytes"),
        ("commit_tx(", "commit_tx"),
    ] {
        if let Some(pos) = find_call_pos(code, needle) {
            let is_method_payload = pos > 0 && code.as_bytes()[pos - 1] == b'.';
            if !is_method_payload
                && let Some(inside) = extract_balanced_paren_body(&code[pos + needle.len()..])
                && let Some(first) = extract_first_literal_arg(inside)
                && let Some(norm) = normalize_write_target(&first)
            {
                record_write_hit(norm, sink, line, out, seen);
            }
        }
    }

    // 4. Storage-scoped `.put("key", ...)` calls (rejecting queues, routers, maps, and URL paths).
    scan_storage_put_call(code, line, out, seen);
}

fn scan_general_write_sinks(
    trimmed: &str,
    language: Language,
    line: usize,
    out: &mut Vec<WriteSinkHit>,
    seen: &mut BTreeSet<(String, usize)>,
) {
    let code = strip_inline_comment(trimmed, language);
    let code = code.trim();
    if code.is_empty() {
        return;
    }

    let sinks = [
        ("fs::write(", "fs::write"),
        ("File::create(", "File::create"),
        ("File::create_new(", "File::create_new"),
        ("writeFileSync(", "writeFileSync"),
        ("writeFile(", "writeFile"),
        ("appendFileSync(", "appendFileSync"),
        ("createWriteStream(", "createWriteStream"),
        ("os.WriteFile(", "os.WriteFile"),
        ("os.Create(", "os.Create"),
        ("commit_tx(", "commit_tx"),
    ];
    for (needle, label) in sinks {
        if let Some(pos) = find_call_pos(code, needle) {
            let after = &code[pos + needle.len()..];
            if let Some(first) = extract_first_literal_arg(after)
                && let Some(norm) = normalize_write_target(&first)
            {
                record_write_hit(norm, label, line, out, seen);
            }
        }
    }

    scan_storage_put_call(code, line, out, seen);
}

fn scan_storage_put_call(
    code: &str,
    line: usize,
    out: &mut Vec<WriteSinkHit>,
    seen: &mut BTreeSet<(String, usize)>,
) {
    let mut start = 0usize;
    while let Some(rel) = code[start..].find(".put(") {
        let abs = start + rel;
        let recv_ident = extract_trailing_ident(&code[..abs]);
        if is_storage_receiver_name(recv_ident)
            && let Some(inside) = extract_balanced_paren_body(&code[abs + 5..])
            && let Some(first) = extract_first_literal_arg(inside)
            && let Some(norm) = normalize_write_target(&first)
            && is_valid_put_target(&norm)
        {
            record_write_hit(norm, "put", line, out, seen);
        }
        start = abs + 5;
    }
}

fn strip_inline_comment(line: &str, language: Language) -> &str {
    let bytes = line.as_bytes();
    let mut in_quote: Option<u8> = None;
    let mut i = 0usize;
    while i < bytes.len() {
        let b = bytes[i];
        if let Some(q) = in_quote {
            if b == b'\\' && i + 1 < bytes.len() {
                i += 2;
                continue;
            }
            if b == q {
                in_quote = None;
            }
            i += 1;
            continue;
        }
        if b == b'"' || b == b'\'' || b == b'`' {
            in_quote = Some(b);
            i += 1;
            continue;
        }
        if matches!(language, Language::Python | Language::Shell) && b == b'#' {
            return &line[..i];
        }
        if !matches!(language, Language::Python | Language::Shell)
            && b == b'/'
            && bytes.get(i + 1) == Some(&b'/')
        {
            return &line[..i];
        }
        i += 1;
    }
    line
}

fn extract_balanced_paren_body(after_open: &str) -> Option<&str> {
    let bytes = after_open.as_bytes();
    let mut depth = 1usize;
    let mut in_quote: Option<u8> = None;
    let mut i = 0usize;
    while i < bytes.len() {
        let b = bytes[i];
        if let Some(q) = in_quote {
            if b == b'\\' && i + 1 < bytes.len() {
                i += 2;
                continue;
            }
            if b == q {
                in_quote = None;
            }
            i += 1;
            continue;
        }
        if b == b'"' || b == b'\'' {
            in_quote = Some(b);
        } else if b == b'(' {
            depth += 1;
        } else if b == b')' {
            depth -= 1;
            if depth == 0 {
                return Some(&after_open[..i]);
            }
        }
        i += 1;
    }
    // Single-line multi-line call fallback: bound to end of line if no closing paren on this line.
    Some(after_open)
}

fn split_top_level_args(body: &str) -> Vec<&str> {
    let bytes = body.as_bytes();
    let mut args = Vec::new();
    let mut start = 0usize;
    let mut paren_depth = 0usize;
    let mut bracket_depth = 0usize;
    let mut in_quote: Option<u8> = None;
    let mut i = 0usize;
    while i < bytes.len() {
        let b = bytes[i];
        if let Some(q) = in_quote {
            if b == b'\\' && i + 1 < bytes.len() {
                i += 2;
                continue;
            }
            if b == q {
                in_quote = None;
            }
            i += 1;
            continue;
        }
        match b {
            b'"' | b'\'' => in_quote = Some(b),
            b'(' => paren_depth += 1,
            b')' => paren_depth = paren_depth.saturating_sub(1),
            b'[' | b'{' => bracket_depth += 1,
            b']' | b'}' => bracket_depth = bracket_depth.saturating_sub(1),
            b',' if paren_depth == 0 && bracket_depth == 0 => {
                args.push(body[start..i].trim());
                start = i + 1;
            }
            _ => {}
        }
        i += 1;
    }
    let tail = body[start..].trim();
    if !tail.is_empty() {
        args.push(tail);
    }
    args
}

/// Extract the immediate receiver expression preceding `.write_text(` / `.write_bytes(`,
/// stopping at statement/assignment/delimiter boundaries outside balanced parens.
fn extract_immediate_receiver(before_dot: &str) -> &str {
    let trimmed = before_dot.trim_end();
    let bytes = trimmed.as_bytes();
    let mut paren_depth = 0usize;
    let mut bracket_depth = 0usize;
    let mut in_quote: Option<u8> = None;
    let mut i = bytes.len();
    while i > 0 {
        i -= 1;
        let b = bytes[i];
        if let Some(q) = in_quote {
            if b == q && (i == 0 || bytes[i - 1] != b'\\') {
                in_quote = None;
            }
            continue;
        }
        match b {
            b'"' | b'\'' => in_quote = Some(b),
            b')' => paren_depth += 1,
            b'(' => {
                if paren_depth == 0 {
                    return trimmed[i + 1..].trim();
                }
                paren_depth -= 1;
            }
            b']' => bracket_depth += 1,
            b'[' => {
                if bracket_depth == 0 {
                    return trimmed[i + 1..].trim();
                }
                bracket_depth -= 1;
            }
            b'=' | b',' | b';' | b':' | b'{' if paren_depth == 0 && bracket_depth == 0 => {
                return trimmed[i + 1..].trim();
            }
            _ => {}
        }
    }
    trimmed
}

fn extract_trailing_ident(before_dot: &str) -> &str {
    let trimmed = before_dot.trim_end();
    let bytes = trimmed.as_bytes();
    let mut start = bytes.len();
    while start > 0 && (bytes[start - 1].is_ascii_alphanumeric() || bytes[start - 1] == b'_') {
        start -= 1;
    }
    &trimmed[start..]
}

fn find_call_pos(line: &str, needle: &str) -> Option<usize> {
    let mut start = 0usize;
    while let Some(rel) = line[start..].find(needle) {
        let abs = start + rel;
        let prev_ok = abs == 0
            || !line[..abs]
                .chars()
                .next_back()
                .is_some_and(|c| c.is_ascii_alphanumeric() || c == '_');
        if prev_ok {
            return Some(abs);
        }
        start = abs + 1;
    }
    None
}

fn is_python_write_mode(mode: &str) -> bool {
    let m = mode.trim();
    !m.is_empty()
        && m.len() <= 4
        && m.chars().all(|c| matches!(c, 'r' | 'w' | 'a' | 'x' | 'b' | 't' | '+'))
        && (m.contains('w') || m.contains('a') || m.contains('x') || m.contains('+'))
}

fn extract_first_literal_arg(after_open_paren: &str) -> Option<String> {
    let trimmed = after_open_paren.trim_start();
    if trimmed.starts_with('"') || trimmed.starts_with('\'') {
        extract_quoted_literals(trimmed).into_iter().next()
    } else {
        None
    }
}

fn extract_quoted_literals(text: &str) -> Vec<String> {
    let chars: Vec<char> = text.chars().collect();
    let mut out = Vec::new();
    let mut i = 0usize;
    while i < chars.len() {
        let ch = chars[i];
        if ch == '"' || ch == '\'' {
            let quote = ch;
            i += 1;
            let mut buf = String::new();
            while i < chars.len() {
                if chars[i] == '\\' && i + 1 < chars.len() {
                    buf.push(chars[i + 1]);
                    i += 2;
                    continue;
                }
                if chars[i] == quote {
                    i += 1;
                    break;
                }
                buf.push(chars[i]);
                i += 1;
            }
            out.push(buf);
            continue;
        }
        i += 1;
    }
    out
}

/// Count `{` and `}` outside quoted string literals and single-line comments.
fn count_structural_braces(line: &str, language: Language) -> (i32, i32) {
    let chars: Vec<char> = line.chars().collect();
    let mut opens = 0i32;
    let mut closes = 0i32;
    let mut i = 0usize;
    let mut in_quote: Option<char> = None;

    while i < chars.len() {
        let ch = chars[i];
        if let Some(q) = in_quote {
            if ch == '\\' && i + 1 < chars.len() {
                i += 2;
                continue;
            }
            if ch == q {
                in_quote = None;
            }
            i += 1;
            continue;
        }

        if language == Language::Shell && ch == '#' {
            break;
        }
        if language != Language::Shell && ch == '/' && chars.get(i + 1) == Some(&'/') {
            break;
        }
        if ch == '"' || ch == '\'' || ch == '`' {
            in_quote = Some(ch);
            i += 1;
            continue;
        }
        if ch == '{' {
            opens += 1;
        } else if ch == '}' {
            closes += 1;
        }
        i += 1;
    }

    (opens, closes)
}

fn scan_python_suppression(
    trimmed: &str,
    lines: &[&str],
    one_based_line: usize,
    out: &mut SuppressionMetrics,
) {
    let lower = trimmed.to_ascii_lowercase();
    for marker in ["# noqa", "# type: ignore", "# pylint: disable"] {
        if let Some(pos) = lower.find(marker) {
            let tail = lower[pos + marker.len()..].trim();
            let is_blanket = tail.is_empty()
                || tail.starts_with('#')
                || (!tail.starts_with(':') && !tail.starts_with('[') && !tail.starts_with('='));
            out.total += 1;
            if is_blanket {
                out.blanket += 1;
            } else {
                out.narrow += 1;
                if has_preceding_comment(lines, one_based_line) {
                    out.justified_narrow += 1;
                }
            }
            if out.directives.len() < 32 {
                out.directives.push(trimmed[pos..].chars().take(60).collect());
            }
        }
    }
}

fn scan_general_suppression(
    trimmed: &str,
    language: Language,
    lines: &[&str],
    one_based_line: usize,
    out: &mut SuppressionMetrics,
) {
    let lower = trimmed.to_ascii_lowercase();
    let markers: &[&str] = match language {
        Language::Rust => &["#![allow(", "#[allow("],
        Language::TypeScript | Language::JavaScript => &[
            "eslint-disable",
            "@ts-ignore",
            "@ts-nocheck",
            "@ts-expect-error",
        ],
        Language::Go => &["//nolint"],
        Language::Shell => &["# shellcheck disable="],
        Language::Python => &[],
    };
    for &marker in markers {
        if let Some(pos) = lower.find(marker) {
            let is_blanket = match marker {
                "#![allow(" | "@ts-nocheck" => true,
                "#[allow(" => {
                    lower.contains("clippy::all") || lower.contains("allow(warnings)")
                }
                "eslint-disable" => is_blanket_eslint_directive(&lower[pos..]),
                "//nolint" => {
                    let tail = lower[pos + marker.len()..].trim();
                    tail.is_empty() || !tail.starts_with(':')
                }
                _ => false,
            };
            out.total += 1;
            if is_blanket {
                out.blanket += 1;
            } else {
                out.narrow += 1;
                if has_preceding_comment(lines, one_based_line) {
                    out.justified_narrow += 1;
                }
            }
            if out.directives.len() < 32 {
                out.directives.push(trimmed.chars().take(60).collect());
            }
        }
    }
}

/// Treat `eslint-disable`, `eslint-disable-next-line`, and `eslint-disable-line`
/// with no specific rule name after them as blanket suppressions.
fn is_blanket_eslint_directive(slice: &str) -> bool {
    let rest = slice
        .strip_prefix("eslint-disable-next-line")
        .or_else(|| slice.strip_prefix("eslint-disable-line"))
        .or_else(|| slice.strip_prefix("eslint-disable"))
        .unwrap_or("");
    let cleaned = rest.trim().trim_end_matches("*/").trim();
    cleaned.is_empty() || cleaned.starts_with("--")
}

fn extract_general_import(
    trimmed: &str,
    language: Language,
    line: usize,
    is_test_or_eval: bool,
    out: &mut BTreeSet<String>,
    paths: &mut BTreeSet<String>,
    reach_ins: &mut Vec<ReachInSignal>,
) {
    match language {
        Language::TypeScript | Language::JavaScript => {
            if let Some(pos) = trimmed.find("from ") {
                let tail = trimmed[pos + 5..].trim().trim_end_matches(';');
                let unquoted = tail.trim_matches(|c| c == '\'' || c == '"');
                if unquoted.starts_with('.') {
                    let cleaned = unquoted
                        .trim_start_matches("./")
                        .trim_end_matches(".ts")
                        .trim_end_matches(".tsx")
                        .trim_end_matches(".js")
                        .trim_end_matches(".mjs");
                    if !cleaned.is_empty() {
                        paths.insert(cleaned.to_string());
                    }
                    if let Some(stem) = cleaned.rsplit('/').next()
                        && !stem.is_empty()
                    {
                        out.insert(stem.to_string());
                    }
                    if !is_test_or_eval && reach_ins.len() < MAX_REACH_INS_PER_FILE {
                        let segs: Vec<&str> = cleaned.split('/').collect();
                        if segs.iter().any(|s| is_private_ident(s))
                            || segs
                                .iter()
                                .any(|s| matches!(*s, "internal" | "private" | "detail"))
                        {
                            reach_ins.push(ReachInSignal {
                                kind: "js_private_or_deep_import".to_string(),
                                target: unquoted.to_string(),
                                line,
                            });
                        }
                    }
                }
            }
        }
        Language::Go if trimmed.starts_with('"') && trimmed.ends_with('"') => {
            let inner = trimmed.trim_matches('"');
            if let Some(last) = inner.rsplit('/').next()
                && !last.is_empty()
            {
                out.insert(last.to_string());
                paths.insert(inner.to_string());
            }
        }
        Language::Rust => {
            if !is_test_or_eval
                && trimmed.starts_with("#[path")
                && let Some(first) = extract_quoted_literals(trimmed).into_iter().next()
                && reach_ins.len() < MAX_REACH_INS_PER_FILE
            {
                reach_ins.push(ReachInSignal {
                    kind: "rust_path_attr".to_string(),
                    target: first,
                    line,
                });
            }
        }
        _ => {}
    }
}

fn detect_brace_fn_header(trimmed: &str, language: Language) -> Option<(String, usize)> {
    match language {
        Language::Rust => {
            let rest = trimmed
                .strip_prefix("pub fn ")
                .or_else(|| trimmed.strip_prefix("pub async fn "))
                .or_else(|| trimmed.strip_prefix("async fn "))
                .or_else(|| trimmed.strip_prefix("fn "))?;
            parse_name_and_params(rest)
        }
        Language::TypeScript | Language::JavaScript => {
            let rest = trimmed
                .strip_prefix("export async function ")
                .or_else(|| trimmed.strip_prefix("export function "))
                .or_else(|| trimmed.strip_prefix("async function "))
                .or_else(|| trimmed.strip_prefix("function "))?;
            parse_name_and_params(rest)
        }
        Language::Go => {
            let rest = trimmed.strip_prefix("func ")?;
            let rest = if rest.starts_with('(') {
                let (_, after) = rest.split_once(')')?;
                after.trim_start()
            } else {
                rest
            };
            parse_name_and_params(rest)
        }
        Language::Shell => {
            if let Some(rest) = trimmed.strip_prefix("function ") {
                let name = rest
                    .split(|c: char| c.is_whitespace() || c == '(' || c == '{')
                    .next()?
                    .to_string();
                if !name.is_empty() {
                    return Some((name, 0));
                }
            } else if trimmed.ends_with("() {") || trimmed.ends_with("(){") {
                let name = trimmed.split('(').next()?.trim().to_string();
                if !name.is_empty() && !name.contains(' ') {
                    return Some((name, 0));
                }
            }
            None
        }
        Language::Python => None,
    }
}

fn parse_name_and_params(rest: &str) -> Option<(String, usize)> {
    let (head, tail) = rest.split_once('(')?;
    let name = head.split('<').next()?.trim().to_string();
    if name.is_empty() {
        return None;
    }
    let params_str = tail.split(')').next().unwrap_or("").trim();
    let count = if params_str.is_empty() {
        0
    } else {
        params_str.split(',').filter(|s| !s.trim().is_empty()).count()
    };
    Some((name, count))
}

fn looks_like_static_data(lines: &[&str]) -> bool {
    let mut data_like = 0usize;
    let mut non_empty = 0usize;
    for line in lines {
        let t = line.trim();
        if t.is_empty() || t.starts_with('#') || t.starts_with("//") {
            continue;
        }
        non_empty += 1;
        if t.ends_with(',') || t.starts_with('"') || t.starts_with('\'') || t.starts_with('(') {
            data_like += 1;
        }
    }
    non_empty >= 40 && data_like.saturating_mul(100) >= non_empty.saturating_mul(65)
}
