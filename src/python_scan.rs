//! Lexical line-state and function-signature scanner for Python sources.
//!
//! Uses a shared per-line/per-byte lexer (`PyLexer`) that tracks triple-quoted
//! strings (`"""..."""`, `'''...'''`), raw and escaped quotes, Python 3.12+
//! PEP 701 f-strings and Python 3.14 t-strings (including nested same-quote
//! expressions and format specs), backslash-continued single-quoted strings,
//! implicit bracket continuations (`()` / `[]` / `{}`), and explicit
//! trailing-`\` line continuations.

use crate::model::FunctionMetrics;

const MAX_INTERP_DEPTH: usize = 64;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct StringLit {
    quote: u8,
    triple: bool,
    interpolated: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum LexMode {
    Code,
    String(StringLit),
    FormatSpec,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct InterpFrame {
    return_mode: LexMode,
    expr_base_depth: usize,
    enclosing_triple: bool,
}

#[derive(Debug, Clone)]
struct PyLexer {
    mode: LexMode,
    bracket_depth: usize,
    frames: Vec<InterpFrame>,
}

impl PyLexer {
    fn new() -> Self {
        Self {
            mode: LexMode::Code,
            bracket_depth: 0,
            frames: Vec::new(),
        }
    }

    fn in_string_or_spec(&self) -> bool {
        matches!(self.mode, LexMode::String(_) | LexMode::FormatSpec)
    }

    fn is_top_level_code(&self) -> bool {
        self.mode == LexMode::Code && self.frames.is_empty()
    }

    /// Advance across one physical line, invoking `on_code_byte(idx, byte, depth_before)`
    /// for every non-comment byte in top-level `Code` mode (outside all strings
    /// and f-string/t-string frames). Returns `(ends_with_backslash, stopped_early)`.
    fn step_line<F>(&mut self, line: &str, mut on_code_byte: F) -> (bool, bool)
    where
        F: FnMut(usize, u8, usize) -> bool,
    {
        let bytes = line.as_bytes();
        let mut i = 0usize;
        let mut ends_with_backslash = false;

        while i < bytes.len() {
            match self.mode {
                LexMode::String(lit) => {
                    let (next_i, hit_eol_bs) = self.step_string_mode(bytes, i, lit);
                    if hit_eol_bs {
                        ends_with_backslash = true;
                    }
                    i = next_i;
                }
                LexMode::FormatSpec => {
                    let (next_i, hit_eol_bs) = self.step_format_spec_mode(bytes, i);
                    if hit_eol_bs {
                        ends_with_backslash = true;
                    }
                    i = next_i;
                }
                LexMode::Code => {
                    let b = bytes[i];
                    if b == b'#' {
                        break;
                    }
                    if b == b'\'' || b == b'"' {
                        i = self.enter_string(bytes, i);
                        continue;
                    }
                    if b == b'\\' && i + 1 == bytes.len() {
                        ends_with_backslash = true;
                        i += 1;
                        continue;
                    }
                    if self.frames.is_empty() && on_code_byte(i, b, self.bracket_depth) {
                        return (ends_with_backslash, true);
                    }
                    self.step_code_delimiter(b);
                    i += 1;
                }
            }
        }

        self.finish_line(ends_with_backslash);
        (ends_with_backslash, false)
    }

    fn enter_string(&mut self, bytes: &[u8], i: usize) -> usize {
        let quote = bytes[i];
        let triple = i + 2 < bytes.len() && bytes[i + 1] == quote && bytes[i + 2] == quote;
        let interpolated = is_interpolated_string_prefix(bytes, i);
        self.mode = LexMode::String(StringLit {
            quote,
            triple,
            interpolated,
        });
        if triple { i + 3 } else { i + 1 }
    }

    fn step_string_mode(&mut self, bytes: &[u8], i: usize, lit: StringLit) -> (usize, bool) {
        if bytes[i] == b'\\' {
            if i + 1 == bytes.len() {
                return (i + 1, !lit.triple);
            }
            if bytes[i + 1] < 0x80 {
                return (i + 2, false);
            }
            return (i + 1, false);
        }

        if lit.triple {
            if i + 2 < bytes.len()
                && bytes[i] == lit.quote
                && bytes[i + 1] == lit.quote
                && bytes[i + 2] == lit.quote
            {
                self.mode = LexMode::Code;
                return (i + 3, false);
            }
        } else if bytes[i] == lit.quote {
            self.mode = LexMode::Code;
            return (i + 1, false);
        }

        if lit.interpolated {
            if bytes[i] == b'{' {
                if i + 1 < bytes.len() && bytes[i + 1] == b'{' {
                    return (i + 2, false);
                }
                if self.frames.len() < MAX_INTERP_DEPTH {
                    self.bracket_depth = self.bracket_depth.saturating_add(1);
                    self.frames.push(InterpFrame {
                        return_mode: LexMode::String(lit),
                        expr_base_depth: self.bracket_depth,
                        enclosing_triple: lit.triple,
                    });
                    self.mode = LexMode::Code;
                }
                return (i + 1, false);
            }
            if bytes[i] == b'}' && i + 1 < bytes.len() && bytes[i + 1] == b'}' {
                return (i + 2, false);
            }
        }

        (i + 1, false)
    }

    fn step_format_spec_mode(&mut self, bytes: &[u8], i: usize) -> (usize, bool) {
        if bytes[i] == b'\\' {
            if i + 1 == bytes.len() {
                let triple = self.frames.last().is_some_and(|f| f.enclosing_triple);
                return (i + 1, !triple);
            }
            if bytes[i + 1] < 0x80 {
                return (i + 2, false);
            }
            return (i + 1, false);
        }

        if bytes[i] == b'{' {
            if i + 1 < bytes.len() && bytes[i + 1] == b'{' {
                return (i + 2, false);
            }
            if self.frames.len() < MAX_INTERP_DEPTH {
                let triple = self.frames.last().is_some_and(|f| f.enclosing_triple);
                self.bracket_depth = self.bracket_depth.saturating_add(1);
                self.frames.push(InterpFrame {
                    return_mode: LexMode::FormatSpec,
                    expr_base_depth: self.bracket_depth,
                    enclosing_triple: triple,
                });
                self.mode = LexMode::Code;
            }
            return (i + 1, false);
        }

        if bytes[i] == b'}' {
            if let Some(frame) = self.frames.pop() {
                self.bracket_depth = self.bracket_depth.saturating_sub(1);
                self.mode = frame.return_mode;
            } else {
                self.mode = LexMode::Code;
            }
            return (i + 1, false);
        }

        (i + 1, false)
    }

    fn step_code_delimiter(&mut self, b: u8) {
        if matches!(b, b'(' | b'[' | b'{') {
            self.bracket_depth = self.bracket_depth.saturating_add(1);
        } else if b == b':' {
            if self
                .frames
                .last()
                .is_some_and(|f| f.expr_base_depth == self.bracket_depth)
            {
                self.mode = LexMode::FormatSpec;
            }
        } else if b == b'}' {
            if self
                .frames
                .last()
                .is_some_and(|f| f.expr_base_depth == self.bracket_depth)
            {
                if let Some(frame) = self.frames.pop() {
                    self.bracket_depth = self.bracket_depth.saturating_sub(1);
                    self.mode = frame.return_mode;
                }
            } else {
                self.bracket_depth = self.bracket_depth.saturating_sub(1);
            }
        } else if matches!(b, b')' | b']') {
            self.bracket_depth = self.bracket_depth.saturating_sub(1);
        }
    }

    fn finish_line(&mut self, ends_with_backslash: bool) {
        if ends_with_backslash {
            return;
        }
        match self.mode {
            LexMode::String(lit) if !lit.triple => {
                self.mode = LexMode::Code;
            }
            LexMode::FormatSpec if !self.frames.last().is_some_and(|f| f.enclosing_triple) => {
                if let Some(frame) = self.frames.pop() {
                    self.bracket_depth = self.bracket_depth.saturating_sub(1);
                    self.mode = match frame.return_mode {
                        LexMode::String(lit) if !lit.triple => LexMode::Code,
                        other => other,
                    };
                } else {
                    self.mode = LexMode::Code;
                }
            }
            _ => {}
        }
    }
}

fn is_interpolated_string_prefix(bytes: &[u8], quote_idx: usize) -> bool {
    let mut start = quote_idx;
    while start > 0 && quote_idx - start < 2 && bytes[start - 1].is_ascii_alphabetic() {
        start -= 1;
    }
    if start == quote_idx {
        return false;
    }
    if start > 0 {
        let prev = bytes[start - 1];
        if prev.is_ascii_alphanumeric() || prev == b'_' || prev >= 0x80 {
            return false;
        }
    }
    let prefix = &bytes[start..quote_idx];
    let mut lower = [0u8; 2];
    for (dst, src) in lower.iter_mut().zip(prefix.iter()) {
        *dst = src.to_ascii_lowercase();
    }
    match prefix.len() {
        1 => matches!(lower[0], b'f' | b't'),
        2 => matches!(
            (lower[0], lower[1]),
            (b'f', b'r') | (b'r', b'f') | (b't', b'r') | (b'r', b't')
        ),
        _ => false,
    }
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
    let mut lexer = PyLexer::new();
    let mut prev_backslash = false;

    for line in lines {
        let starts_in_string = lexer.in_string_or_spec();
        let starts_from_backslash = prev_backslash;
        let start_bracket_depth = lexer.bracket_depth;

        let (ends_with_backslash, _) = lexer.step_line(line, |_, _, _| false);
        let ends_in_string = lexer.in_string_or_spec();

        states.push(PyLineState {
            starts_in_string,
            starts_from_backslash,
            start_bracket_depth,
            ends_in_string,
            ends_with_backslash,
            end_bracket_depth: lexer.bracket_depth,
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
        if states
            .get(idx)
            .is_some_and(PyLineState::starts_in_continuation)
        {
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
    let mut lexer = PyLexer::new();
    let mut phase = HeaderPhase::Before;
    let mut param_count = 0usize;
    let mut current_param = String::new();
    let mut lambda_depth = 0usize;

    for (offset, line) in lines.iter().skip(start_idx).enumerate() {
        let line_idx = start_idx + offset;
        let bytes = line.as_bytes();
        let mut colon_idx: Option<usize> = None;

        let (_, stopped) = lexer.step_line(line, |i, b, depth| match phase {
            HeaderPhase::Before => {
                if b == b'(' && depth == 0 {
                    phase = HeaderPhase::Params;
                } else if b == b':' && depth == 0 {
                    colon_idx = Some(i);
                    return true;
                }
                false
            }
            HeaderPhase::Params => {
                if depth == 1 && lambda_depth == 0 && b == b',' {
                    if is_counted_param(&current_param) {
                        param_count += 1;
                    }
                    current_param.clear();
                } else if depth == 1 && b == b')' {
                    if is_counted_param(&current_param) {
                        param_count += 1;
                    }
                    current_param.clear();
                    lambda_depth = 0;
                    phase = HeaderPhase::After;
                } else if depth == 1 && !matches!(b, b'(' | b'[' | b'{' | b']' | b'}') {
                    if lambda_depth > 0 && b == b':' {
                        lambda_depth -= 1;
                    } else if is_lambda_keyword_at(bytes, i) {
                        lambda_depth = lambda_depth.saturating_add(1);
                    }
                    push_param_byte(&mut current_param, b);
                }
                false
            }
            HeaderPhase::After => {
                if b == b':' && depth == 0 {
                    colon_idx = Some(i);
                    return true;
                }
                false
            }
        });

        if stopped && let Some(ci) = colon_idx {
            return PyHeaderInfo {
                header_end_idx: line_idx,
                param_count,
                has_inline_suite: has_inline_py_suite(&line[ci + 1..]),
            };
        }

        if phase == HeaderPhase::Params && lexer.is_top_level_code() && lexer.bracket_depth == 1 {
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
    if buf.is_empty() && byte.is_ascii_whitespace() {
        return;
    }
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
    if let Some(after_async) = trimmed.strip_prefix("async")
        && let Some(rest) = strip_horizontal_ws(after_async)
    {
        return has_kw_delim(rest, "for") || has_kw_delim(rest, "with");
    }
    if let Some(after_try) = trimmed.strip_prefix("try") {
        return after_try.trim_start_matches([' ', '\t']).starts_with(':');
    }
    has_kw_delim(trimmed, "if")
        || has_kw_delim(trimmed, "for")
        || has_kw_delim(trimmed, "while")
        || has_kw_delim(trimmed, "with")
        || has_kw_delim(trimmed, "match")
}

fn has_kw_delim(s: &str, kw: &str) -> bool {
    s.strip_prefix(kw)
        .is_some_and(|rest| rest.starts_with([' ', '\t', '(']))
}
