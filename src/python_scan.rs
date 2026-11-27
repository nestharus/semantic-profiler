//! Lexical line-state and function-signature scanner for Python sources.
//!
//! Tracks multiline triple-quoted strings (`"""..."""`, `'''...'''`),
//! backslash-continued single-quoted strings, implicit bracket continuations
//! (`()` / `[]` / `{}`), and explicit trailing-`\` line continuations so that
//! multiline `def` / `async def` signatures, multiline return annotations,
//! parameter counts, and indented function bodies match Python's own syntax.

use crate::model::FunctionMetrics;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum StringState {
    None,
    Single(u8),
    Triple(u8),
}

/// Lexical continuation state at the start and end of a physical Python line.
#[derive(Debug, Clone, Copy, Default)]
pub struct PyLineState {
    starts_in_string: bool,
    starts_from_backslash: bool,
    start_bracket_depth: usize,
    ends_in_string: bool,
    ends_with_backslash: bool,
    end_bracket_depth: usize,
}

impl PyLineState {
    /// True when this physical line begins inside a multiline string literal.
    pub fn starts_in_string(&self) -> bool {
        self.starts_in_string
    }

    /// True when this physical line continues the previous logical line
    /// (multiline string, unclosed `()`/`[]`/`{}`, or trailing `\`).
    pub fn starts_in_continuation(&self) -> bool {
        self.starts_in_string || self.start_bracket_depth > 0 || self.starts_from_backslash
    }

    /// True when this physical line leaves a logical line open onto the next line.
    pub fn ends_in_continuation(&self) -> bool {
        self.ends_in_string || self.end_bracket_depth > 0 || self.ends_with_backslash
    }
}

/// Compute per-line lexical continuation state across an entire Python source.
pub fn scan_python_line_states(lines: &[&str]) -> Vec<PyLineState> {
    let mut states = Vec::with_capacity(lines.len());
    let mut string_state = StringState::None;
    let mut bracket_depth = 0usize;
    let mut prev_backslash = false;

    for line in lines {
        let starts_in_string = string_state != StringState::None;
        let starts_from_backslash = prev_backslash;
        let start_bracket_depth = bracket_depth;

        let ends_with_backslash = advance_line_lexer(line, &mut string_state, &mut bracket_depth);
        let ends_in_string = string_state != StringState::None;

        states.push(PyLineState {
            starts_in_string,
            starts_from_backslash,
            start_bracket_depth,
            ends_in_string,
            ends_with_backslash,
            end_bracket_depth: bracket_depth,
        });
        prev_backslash = ends_with_backslash;
    }

    states
}

/// Scan all `def` and `async def` functions in a Python file using precomputed
/// lexical line states.
pub fn scan_python_functions(lines: &[&str], states: &[PyLineState]) -> Vec<FunctionMetrics> {
    let mut functions = Vec::new();
    for (idx, line) in lines.iter().enumerate() {
        if states.get(idx).is_some_and(PyLineState::starts_in_continuation) {
            continue;
        }
        let Some(name) = parse_def_name(line.trim()) else {
            continue;
        };
        let def_indent = indent_width(line);
        let header = parse_py_header(lines, idx);
        let (end_idx, max_nesting) = measure_py_body(lines, states, def_indent, &header);

        let start_line = idx + 1;
        let end_line = end_idx + 1;
        functions.push(FunctionMetrics {
            name,
            start_line,
            end_line,
            loc: end_line.saturating_sub(start_line) + 1,
            param_count: header.param_count,
            max_nesting_depth: max_nesting,
            is_flat_dispatcher: false,
        });
    }
    functions
}

fn advance_line_lexer(
    line: &str,
    string_state: &mut StringState,
    bracket_depth: &mut usize,
) -> bool {
    let bytes = line.as_bytes();
    let mut i = 0usize;
    let mut ends_with_backslash = false;

    while i < bytes.len() {
        match *string_state {
            StringState::Triple(q) => {
                i = step_triple_string(bytes, i, q, string_state);
            }
            StringState::Single(q) => {
                let (next_i, hit_eol_bs) = step_single_string(bytes, i, q, string_state);
                if hit_eol_bs {
                    ends_with_backslash = true;
                }
                i = next_i;
            }
            StringState::None => {
                let b = bytes[i];
                if b == b'#' {
                    break;
                }
                if b == b'\'' || b == b'"' {
                    i = enter_string_literal(bytes, i, string_state);
                } else if b == b'\\' && i + 1 == bytes.len() {
                    ends_with_backslash = true;
                    i += 1;
                } else if matches!(b, b'(' | b'[' | b'{') {
                    *bracket_depth = bracket_depth.saturating_add(1);
                    i += 1;
                } else if matches!(b, b')' | b']' | b'}') {
                    *bracket_depth = bracket_depth.saturating_sub(1);
                    i += 1;
                } else {
                    i += 1;
                }
            }
        }
    }

    if matches!(*string_state, StringState::Single(_)) && !ends_with_backslash {
        *string_state = StringState::None;
    }

    ends_with_backslash
}

fn enter_string_literal(bytes: &[u8], i: usize, string_state: &mut StringState) -> usize {
    let q = bytes[i];
    if i + 2 < bytes.len() && bytes[i + 1] == q && bytes[i + 2] == q {
        *string_state = StringState::Triple(q);
        i + 3
    } else {
        *string_state = StringState::Single(q);
        i + 1
    }
}

fn step_triple_string(bytes: &[u8], i: usize, q: u8, string_state: &mut StringState) -> usize {
    if bytes[i] == b'\\' {
        if i + 1 < bytes.len() && bytes[i + 1] < 0x80 {
            return i + 2;
        }
        return i + 1;
    }
    if i + 2 < bytes.len() && bytes[i] == q && bytes[i + 1] == q && bytes[i + 2] == q {
        *string_state = StringState::None;
        return i + 3;
    }
    i + 1
}

fn step_single_string(
    bytes: &[u8],
    i: usize,
    q: u8,
    string_state: &mut StringState,
) -> (usize, bool) {
    if bytes[i] == b'\\' {
        if i + 1 == bytes.len() {
            return (i + 1, true);
        }
        if bytes[i + 1] < 0x80 {
            return (i + 2, false);
        }
        return (i + 1, false);
    }
    if bytes[i] == q {
        *string_state = StringState::None;
    }
    (i + 1, false)
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum HeaderPhase {
    Before,
    Params,
    After,
}

#[derive(Debug, Clone, Copy)]
struct PyHeaderInfo {
    header_end_idx: usize,
    param_count: usize,
    has_inline_suite: bool,
}

fn parse_py_header(lines: &[&str], start_idx: usize) -> PyHeaderInfo {
    let mut phase = HeaderPhase::Before;
    let mut string_state = StringState::None;
    let mut depth = 0usize;
    let mut param_count = 0usize;
    let mut current_param = String::new();
    let mut in_lambda_params = false;

    for (offset, line) in lines.iter().skip(start_idx).enumerate() {
        let line_idx = start_idx + offset;
        let bytes = line.as_bytes();
        let mut i = 0usize;
        let mut eol_backslash = false;

        while i < bytes.len() {
            match string_state {
                StringState::Triple(q) => {
                    i = step_triple_string(bytes, i, q, &mut string_state);
                    continue;
                }
                StringState::Single(q) => {
                    let (next_i, hit_bs) = step_single_string(bytes, i, q, &mut string_state);
                    if hit_bs {
                        eol_backslash = true;
                    }
                    i = next_i;
                    continue;
                }
                StringState::None => {}
            }

            let b = bytes[i];
            if b == b'#' {
                break;
            }
            if b == b'\'' || b == b'"' {
                i = enter_string_literal(bytes, i, &mut string_state);
                continue;
            }

            match phase {
                HeaderPhase::Before => {
                    if b == b'(' && depth == 0 {
                        phase = HeaderPhase::Params;
                        depth = 1;
                    } else if matches!(b, b'(' | b'[' | b'{') {
                        depth = depth.saturating_add(1);
                    } else if matches!(b, b')' | b']' | b'}') {
                        depth = depth.saturating_sub(1);
                    } else if b == b':' && depth == 0 {
                        return PyHeaderInfo {
                            header_end_idx: line_idx,
                            param_count,
                            has_inline_suite: has_inline_py_suite(&line[i + 1..]),
                        };
                    }
                }
                HeaderPhase::Params => {
                    if depth == 1 && !in_lambda_params && b == b',' {
                        if is_counted_param(&current_param) {
                            param_count += 1;
                        }
                        current_param.clear();
                    } else if depth == 1 && b == b')' {
                        if is_counted_param(&current_param) {
                            param_count += 1;
                        }
                        current_param.clear();
                        in_lambda_params = false;
                        depth = 0;
                        phase = HeaderPhase::After;
                    } else if matches!(b, b'(' | b'[' | b'{') {
                        depth = depth.saturating_add(1);
                    } else if matches!(b, b')' | b']' | b'}') {
                        depth = depth.saturating_sub(1);
                    } else if depth == 1 {
                        if in_lambda_params && b == b':' {
                            in_lambda_params = false;
                        } else if !in_lambda_params && is_lambda_keyword_at(bytes, i) {
                            in_lambda_params = true;
                        }
                        if !(b == b'\\' && i + 1 == bytes.len()) {
                            push_param_byte(&mut current_param, b);
                        }
                    }
                }
                HeaderPhase::After => {
                    if matches!(b, b'(' | b'[' | b'{') {
                        depth = depth.saturating_add(1);
                    } else if matches!(b, b')' | b']' | b'}') {
                        depth = depth.saturating_sub(1);
                    } else if b == b':' && depth == 0 {
                        return PyHeaderInfo {
                            header_end_idx: line_idx,
                            param_count,
                            has_inline_suite: has_inline_py_suite(&line[i + 1..]),
                        };
                    }
                }
            }
            i += 1;
        }

        if matches!(string_state, StringState::Single(_)) && !eol_backslash {
            string_state = StringState::None;
        }
        if phase == HeaderPhase::Params && depth == 1 && string_state == StringState::None {
            push_param_byte(&mut current_param, b' ');
        }
    }

    PyHeaderInfo {
        header_end_idx: start_idx,
        param_count,
        has_inline_suite: false,
    }
}

fn is_lambda_keyword_at(bytes: &[u8], i: usize) -> bool {
    const KW: &[u8] = b"lambda";
    if !bytes[i..].starts_with(KW) {
        return false;
    }
    let prev_ok = i == 0 || !is_ascii_ident_byte(bytes[i - 1]);
    let next_idx = i + KW.len();
    let next_ok = next_idx >= bytes.len() || !is_ascii_ident_byte(bytes[next_idx]);
    prev_ok && next_ok
}

fn is_ascii_ident_byte(b: u8) -> bool {
    b.is_ascii_alphanumeric() || b == b'_'
}

fn push_param_byte(buf: &mut String, byte: u8) {
    if buf.len() >= 256 {
        return;
    }
    if byte < 0x80 {
        buf.push(byte as char);
    } else {
        buf.push('_');
    }
}

fn is_counted_param(raw: &str) -> bool {
    let trimmed = raw.trim();
    if trimmed.is_empty() {
        return false;
    }
    let name = trimmed.split([':', '=']).next().unwrap_or("").trim();
    !name.is_empty() && !matches!(name, "self" | "cls" | "/" | "*")
}

fn has_inline_py_suite(after_colon: &str) -> bool {
    let trimmed = after_colon.trim();
    !trimmed.is_empty() && !trimmed.starts_with('#')
}

fn measure_py_body(
    lines: &[&str],
    states: &[PyLineState],
    def_indent: usize,
    header: &PyHeaderInfo,
) -> (usize, usize) {
    if header.has_inline_suite {
        let mut end_idx = header.header_end_idx;
        let mut j = header.header_end_idx + 1;
        while j < lines.len()
            && states
                .get(j)
                .is_some_and(PyLineState::starts_in_continuation)
        {
            if states[j].starts_in_string() || is_non_comment_code(lines[j]) {
                end_idx = j;
            }
            j += 1;
        }
        return (end_idx, 0);
    }

    let mut end_idx = header.header_end_idx;
    let mut max_nesting = 0usize;
    let mut block_indents: Vec<usize> = Vec::new();

    let mut j = header.header_end_idx + 1;
    while j < lines.len() {
        let cur = lines[j];
        let st = states.get(j).copied().unwrap_or_default();
        if st.starts_in_continuation() {
            if st.starts_in_string() || is_non_comment_code(cur) {
                end_idx = j;
            }
            j += 1;
            continue;
        }

        let cur_trimmed = cur.trim();
        if cur_trimmed.is_empty() || cur_trimmed.starts_with('#') {
            j += 1;
            continue;
        }

        let ind = indent_width(cur);
        if ind <= def_indent {
            break;
        }
        end_idx = j;

        while let Some(&top) = block_indents.last() {
            if ind <= top {
                block_indents.pop();
            } else {
                break;
            }
        }
        if is_py_control_header(cur_trimmed) {
            block_indents.push(ind);
            if block_indents.len() > max_nesting {
                max_nesting = block_indents.len();
            }
        }
        j += 1;
    }

    (end_idx, max_nesting)
}

fn is_non_comment_code(line: &str) -> bool {
    let trimmed = line.trim();
    !trimmed.is_empty() && !trimmed.starts_with('#')
}

fn parse_def_name(trimmed: &str) -> Option<String> {
    let rest = if let Some(after_async) = trimmed.strip_prefix("async") {
        let after_ws = strip_horizontal_ws(after_async)?;
        let after_def = after_ws.strip_prefix("def")?;
        strip_horizontal_ws(after_def)?
    } else {
        let after_def = trimmed.strip_prefix("def")?;
        strip_horizontal_ws(after_def)?
    };

    let name: String = rest
        .chars()
        .take_while(|c| c.is_alphanumeric() || *c == '_')
        .collect();
    if name.is_empty() || name.chars().next().is_some_and(|c| c.is_ascii_digit()) {
        return None;
    }
    Some(name)
}

fn strip_horizontal_ws(s: &str) -> Option<&str> {
    let trimmed = s.trim_start_matches([' ', '\t']);
    if trimmed.len() == s.len() {
        None
    } else {
        Some(trimmed)
    }
}

fn indent_width(line: &str) -> usize {
    line.chars()
        .take_while(|c| *c == ' ' || *c == '\t')
        .map(|c| if c == '\t' { 4 } else { 1 })
        .sum()
}

fn is_py_control_header(trimmed: &str) -> bool {
    trimmed.starts_with("if ")
        || trimmed.starts_with("if(")
        || trimmed.starts_with("for ")
        || trimmed.starts_with("async for ")
        || trimmed.starts_with("while ")
        || trimmed.starts_with("while(")
        || trimmed.starts_with("with ")
        || trimmed.starts_with("async with ")
        || trimmed.starts_with("try:")
        || trimmed.starts_with("match ")
}
