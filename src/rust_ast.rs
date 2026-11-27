//! Real Rust AST semantic analysis powered by `syn` and `proc-macro2` spans.

use crate::model::{
    FileClassification, FunctionMetrics, ReachInSignal, SuppressionMetrics, WriteSinkHit,
    is_ephemeral_write_target,
};
use std::collections::BTreeSet;
use syn::punctuated::Punctuated;
use syn::spanned::Spanned;
use syn::visit::{self, Visit};
use syn::{Attribute, Block, Expr, ImplItem, Item, Lit, Meta, Token, TraitItem, UseTree};

const MAX_WRITE_SINKS_PER_FILE: usize = 128;
const MAX_REACH_INS_PER_FILE: usize = 128;

#[derive(Debug)]
pub struct AnalyzedUnit {
    pub total_loc: usize,
    pub prod_loc: usize,
    pub inline_test_loc: usize,
    pub est_tokens: usize,
    pub functions: Vec<FunctionMetrics>,
    pub suppressions: SuppressionMetrics,
    pub internal_imports: Vec<String>,
    pub import_paths: Vec<String>,
    pub mod_decl_paths: Vec<String>,
    pub reach_ins: Vec<ReachInSignal>,
    pub write_targets: Vec<WriteSinkHit>,
    pub detected_classification: FileClassification,
    pub parse_fallback: bool,
}

struct AstCollector<'a> {
    lines: &'a [&'a str],
    test_ranges: Vec<(usize, usize)>,
    functions: Vec<FunctionMetrics>,
    suppressions: SuppressionMetrics,
    imports: BTreeSet<String>,
    import_paths: BTreeSet<String>,
    mod_decl_paths: BTreeSet<String>,
    reach_ins: Vec<ReachInSignal>,
    write_targets: Vec<WriteSinkHit>,
    seen_writes: BTreeSet<(String, usize)>,
    mod_stack: Vec<String>,
    const_data_lines: usize,
}

impl<'a> AstCollector<'a> {
    fn new(lines: &'a [&'a str]) -> Self {
        Self {
            lines,
            test_ranges: Vec::new(),
            functions: Vec::new(),
            suppressions: SuppressionMetrics::default(),
            imports: BTreeSet::new(),
            import_paths: BTreeSet::new(),
            mod_decl_paths: BTreeSet::new(),
            reach_ins: Vec::new(),
            write_targets: Vec::new(),
            seen_writes: BTreeSet::new(),
            mod_stack: Vec::new(),
            const_data_lines: 0,
        }
    }

    fn record_reach_in(&mut self, kind: &str, target: String, line: usize) {
        if self.reach_ins.len() < MAX_REACH_INS_PER_FILE {
            self.reach_ins.push(ReachInSignal {
                kind: kind.to_string(),
                target,
                line,
            });
        }
    }

    fn scan_block_writes(&mut self, block: &Block) {
        if self.write_targets.len() >= MAX_WRITE_SINKS_PER_FILE {
            return;
        }
        let mut visitor = WriteSinkVisitor {
            hits: &mut self.write_targets,
            seen: &mut self.seen_writes,
        };
        visitor.visit_block(block);
    }

    fn visit_item(&mut self, item: &Item, in_test_context: bool) {
        let attrs = item_attrs(item);
        let item_is_test = in_test_context || has_test_cfg(attrs) || has_test_attr(attrs);

        if !in_test_context && item_is_test {
            let span = item.span();
            let start = span.start().line;
            let end = span.end().line;
            if start > 0 && end >= start {
                self.test_ranges.push((start, end));
            }
            return;
        }

        if !item_is_test {
            collect_suppressions(attrs, self.lines, &mut self.suppressions, false);
        }

        match item {
            Item::Fn(item_fn) if !item_is_test => {
                self.functions.push(measure_fn(
                    item_fn.sig.ident.to_string(),
                    item_fn.sig.inputs.len(),
                    item_fn.span(),
                    &item_fn.block,
                ));
                self.scan_block_writes(&item_fn.block);
            }
            Item::Impl(item_impl) => {
                for impl_item in &item_impl.items {
                    if let ImplItem::Fn(method) = impl_item {
                        let method_is_test = item_is_test
                            || has_test_cfg(&method.attrs)
                            || has_test_attr(&method.attrs);
                        if !in_test_context && method_is_test {
                            let span = method.span();
                            self.test_ranges.push((span.start().line, span.end().line));
                            continue;
                        }
                        if !method_is_test {
                            collect_suppressions(
                                &method.attrs,
                                self.lines,
                                &mut self.suppressions,
                                false,
                            );
                            self.functions.push(measure_fn(
                                method.sig.ident.to_string(),
                                method.sig.inputs.len(),
                                method.span(),
                                &method.block,
                            ));
                            self.scan_block_writes(&method.block);
                        }
                    }
                }
            }
            Item::Trait(item_trait) => {
                for trait_item in &item_trait.items {
                    if let TraitItem::Fn(method) = trait_item {
                        if !item_is_test {
                            collect_suppressions(
                                &method.attrs,
                                self.lines,
                                &mut self.suppressions,
                                false,
                            );
                        }
                        if !item_is_test
                            && let Some(block) = &method.default
                        {
                            self.functions.push(measure_fn(
                                method.sig.ident.to_string(),
                                method.sig.inputs.len(),
                                method.span(),
                                block,
                            ));
                            self.scan_block_writes(block);
                        }
                    }
                }
            }
            Item::Mod(item_mod) => {
                if !item_is_test {
                    let path_attr = extract_path_attr(&item_mod.attrs);
                    if let Some((ref path_val, line)) = path_attr {
                        self.record_reach_in("rust_path_attr", path_val.clone(), line);
                    }
                    if item_mod.content.is_none() {
                        if let Some((path_val, _)) = path_attr {
                            if let Some(norm) = normalize_rust_path_attr(&path_val, &self.mod_stack)
                            {
                                self.mod_decl_paths.insert(norm);
                            }
                        } else {
                            let mod_name = item_mod.ident.to_string();
                            let mut segs = Vec::with_capacity(self.mod_stack.len() + 2);
                            segs.push("self".to_string());
                            segs.extend(self.mod_stack.iter().cloned());
                            segs.push(mod_name);
                            self.mod_decl_paths.insert(segs.join("/"));
                        }
                    }
                }
                if let Some((_, sub_items)) = &item_mod.content {
                    self.mod_stack.push(item_mod.ident.to_string());
                    for sub in sub_items {
                        self.visit_item(sub, item_is_test);
                    }
                    self.mod_stack.pop();
                }
            }
            Item::Use(item_use) if !item_is_test => {
                let use_line = item_use.span().start().line;
                extract_internal_use(
                    &item_use.tree,
                    Vec::new(),
                    use_line,
                    &mut self.imports,
                    &mut self.import_paths,
                    &mut self.reach_ins,
                );
            }
            Item::Const(item_const)
                if !item_is_test && is_data_literal_expr(&item_const.expr) =>
            {
                let span = item_const.span();
                self.const_data_lines += span.end().line.saturating_sub(span.start().line) + 1;
            }
            Item::Static(item_static)
                if !item_is_test && is_data_literal_expr(&item_static.expr) =>
            {
                let span = item_static.span();
                self.const_data_lines += span.end().line.saturating_sub(span.start().line) + 1;
            }
            _ => {}
        }
    }
}

pub fn analyze_rust_source(source: &str, is_test_or_eval: bool) -> Option<AnalyzedUnit> {
    let file = syn::parse_file(source).ok()?;
    let lines: Vec<&str> = source.lines().collect();
    let total_loc = lines.len();

    let mut collector = AstCollector::new(&lines);
    if !is_test_or_eval {
        collect_suppressions(&file.attrs, &lines, &mut collector.suppressions, true);
    }

    for item in &file.items {
        collector.visit_item(item, is_test_or_eval);
    }

    let inline_test_loc = if is_test_or_eval {
        0
    } else {
        merged_line_count(&collector.test_ranges, total_loc)
    };
    let prod_loc = if is_test_or_eval {
        0
    } else {
        total_loc.saturating_sub(inline_test_loc)
    };

    let prod_token_source = if is_test_or_eval || collector.test_ranges.is_empty() {
        source.to_string()
    } else {
        strip_line_ranges(&lines, &collector.test_ranges)
    };
    let est_tokens = if is_test_or_eval {
        estimate_tokens(source)
    } else {
        estimate_tokens(&prod_token_source)
    };

    let detected_classification = if is_test_or_eval {
        FileClassification::TestOrEval
    } else if collector.functions.is_empty()
        && collector.const_data_lines >= 40
        && collector.const_data_lines.saturating_mul(100) >= prod_loc.saturating_mul(60)
        && collector.suppressions.blanket == 0
    {
        FileClassification::StaticDataTable
    } else if !collector.functions.is_empty()
        && collector.functions.iter().any(|f| f.is_flat_dispatcher)
        && collector.functions.iter().all(|f| f.max_nesting_depth <= 3)
        && collector.suppressions.blanket == 0
    {
        FileClassification::FlatDispatcher
    } else {
        FileClassification::Standard
    };

    Some(AnalyzedUnit {
        total_loc,
        prod_loc,
        inline_test_loc,
        est_tokens,
        functions: collector.functions,
        suppressions: collector.suppressions,
        internal_imports: collector.imports.into_iter().collect(),
        import_paths: collector.import_paths.into_iter().collect(),
        mod_decl_paths: collector.mod_decl_paths.into_iter().collect(),
        reach_ins: collector.reach_ins,
        write_targets: collector.write_targets,
        detected_classification,
        parse_fallback: false,
    })
}

struct WriteSinkVisitor<'a> {
    hits: &'a mut Vec<WriteSinkHit>,
    seen: &'a mut BTreeSet<(String, usize)>,
}

impl WriteSinkVisitor<'_> {
    fn record(&mut self, target: String, sink: &str, line: usize) {
        if self.hits.len() >= MAX_WRITE_SINKS_PER_FILE {
            return;
        }
        if self.seen.insert((target.clone(), line)) {
            self.hits.push(WriteSinkHit {
                target,
                sink: sink.to_string(),
                line,
            });
        }
    }
}

impl<'ast> Visit<'ast> for WriteSinkVisitor<'_> {
    fn visit_expr_call(&mut self, node: &'ast syn::ExprCall) {
        if let Expr::Path(ep) = node.func.as_ref() {
            let segs: Vec<String> = ep
                .path
                .segments
                .iter()
                .map(|s| s.ident.to_string())
                .collect();
            let last = segs.last().map(String::as_str).unwrap_or("");
            let prev = segs
                .len()
                .checked_sub(2)
                .and_then(|idx| segs.get(idx))
                .map(String::as_str)
                .unwrap_or("");
            let sink_label = match (prev, last) {
                ("fs", "write") => Some("fs::write"),
                ("File", "create") => Some("File::create"),
                ("File", "create_new") => Some("File::create_new"),
                (_, "write_text") => Some("write_text"),
                (_, "write_bytes") => Some("write_bytes"),
                (_, "commit_tx") => Some("commit_tx"),
                _ => None,
            };
            if let Some(sink) = sink_label
                && let Some(first_arg) = node.args.first()
                && let Some(target) = extract_target_literal(first_arg)
            {
                self.record(target, sink, node.span().start().line);
            }
        }
        visit::visit_expr_call(self, node);
    }

    fn visit_expr_method_call(&mut self, node: &'ast syn::ExprMethodCall) {
        let method = node.method.to_string();
        let line = node.span().start().line;
        match method.as_str() {
            "open" if chain_has_write_open_options(&node.receiver) => {
                if let Some(first_arg) = node.args.first()
                    && let Some(target) = extract_target_literal(first_arg)
                {
                    self.record(target, "OpenOptions::open(write)", line);
                }
            }
            "put" => {
                if expr_is_storage_like_receiver(&node.receiver)
                    && let Some(first_arg) = node.args.first()
                    && let Some(target) = extract_target_literal(first_arg)
                    && is_valid_put_target(&target)
                {
                    self.record(target, "put", line);
                }
            }
            "write_text" | "write_bytes" | "put_indexed" | "commit_tx" => {
                if let Some(first_arg) = node.args.first()
                    && let Some(target) = extract_target_literal(first_arg)
                {
                    self.record(target, &method, line);
                }
            }
            _ => {}
        }
        visit::visit_expr_method_call(self, node);
    }
}

fn is_lit_false(expr: Option<&Expr>) -> bool {
    matches!(
        expr,
        Some(Expr::Lit(syn::ExprLit {
            lit: Lit::Bool(b),
            ..
        })) if !b.value
    )
}

fn chain_has_write_open_options(expr: &Expr) -> bool {
    let mut cur = expr;
    let mut has_write_flag = false;
    let mut mentions_open_options = false;
    let mut hops = 0usize;
    while hops < 16 {
        hops += 1;
        match cur {
            Expr::MethodCall(mc) => {
                let m = mc.method.to_string();
                if matches!(m.as_str(), "write" | "create" | "create_new" | "append" | "truncate")
                    && !is_lit_false(mc.args.first())
                {
                    has_write_flag = true;
                }
                cur = &mc.receiver;
            }
            Expr::Call(call) => {
                if let Expr::Path(ep) = call.func.as_ref()
                    && ep
                        .path
                        .segments
                        .iter()
                        .any(|s| s.ident == "OpenOptions")
                {
                    mentions_open_options = true;
                }
                break;
            }
            Expr::Reference(r) => cur = &r.expr,
            Expr::Group(g) => cur = &g.expr,
            _ => break,
        }
    }
    has_write_flag && mentions_open_options
}

fn expr_is_storage_like_receiver(expr: &Expr) -> bool {
    let name = match expr {
        Expr::Path(ep) => ep
            .path
            .segments
            .last()
            .map(|s| s.ident.to_string())
            .unwrap_or_default(),
        Expr::Field(ef) => match &ef.member {
            syn::Member::Named(id) => id.to_string(),
            syn::Member::Unnamed(_) => String::new(),
        },
        Expr::MethodCall(mc) => mc.method.to_string(),
        Expr::Reference(r) => return expr_is_storage_like_receiver(&r.expr),
        Expr::Group(g) => return expr_is_storage_like_receiver(&g.expr),
        _ => String::new(),
    };
    is_storage_receiver_name(&name)
}

pub fn is_storage_receiver_name(name: &str) -> bool {
    let lower = name.trim().to_ascii_lowercase();
    if lower.is_empty() {
        return false;
    }
    // Reject obvious non-storage receivers like queues, channels, HTTP routers, or in-memory maps.
    for non_storage in [
        "queue", "router", "http", "req", "res", "resp", "channel", "sender", "tx", "map", "dict",
        "cache", "header", "headers", "app",
    ] {
        if lower == non_storage || lower.ends_with(&format!("_{non_storage}")) {
            return false;
        }
    }
    [
        "store", "storage", "db", "kv", "ledger", "journal", "repo", "engine", "state", "bucket",
        "blob", "catalog", "wal", "persist", "disk", "file", "fs",
    ]
    .iter()
    .any(|kw| lower.contains(kw))
}

pub fn is_valid_put_target(target: &str) -> bool {
    !target.starts_with('/') && !target.contains("://")
}

fn extract_target_literal(expr: &Expr) -> Option<String> {
    match expr {
        Expr::Lit(lit) => {
            if let Lit::Str(s) = &lit.lit {
                normalize_write_target(&s.value())
            } else {
                None
            }
        }
        Expr::Reference(r) => extract_target_literal(&r.expr),
        Expr::Group(g) => extract_target_literal(&g.expr),
        Expr::Call(call) => {
            if let Expr::Path(ep) = call.func.as_ref() {
                let last = ep
                    .path
                    .segments
                    .last()
                    .map(|s| s.ident.to_string())
                    .unwrap_or_default();
                if matches!(last.as_str(), "new" | "from")
                    && let Some(arg) = call.args.first()
                {
                    return extract_target_literal(arg);
                }
            }
            None
        }
        Expr::MethodCall(mc) => {
            let m = mc.method.to_string();
            match m.as_str() {
                "join" => {
                    let arg_lit = mc.args.first().and_then(extract_target_literal)?;
                    if let Some(recv_lit) = extract_raw_literal(&mc.receiver) {
                        let combined = format!(
                            "{}/{}",
                            recv_lit.trim().replace('\\', "/").trim_end_matches('/'),
                            arg_lit.trim_start_matches('/')
                        );
                        normalize_write_target(&combined)
                    } else {
                        Some(arg_lit)
                    }
                }
                "as_ref" | "as_path" | "as_str" | "to_string" | "to_owned" | "to_path_buf" => {
                    extract_target_literal(&mc.receiver)
                }
                _ => None,
            }
        }
        Expr::Macro(mac) => {
            let is_format = mac
                .mac
                .path
                .segments
                .last()
                .is_some_and(|s| s.ident == "format");
            if is_format {
                let args = mac
                    .mac
                    .parse_body_with(Punctuated::<Expr, Token![,]>::parse_terminated)
                    .ok()?;
                let Some(Expr::Lit(syn::ExprLit {
                    lit: Lit::Str(fmt_lit),
                    ..
                })) = args.first()
                else {
                    return None;
                };
                extract_format_write_prefix(&fmt_lit.value())
            } else {
                None
            }
        }
        _ => None,
    }
}

fn extract_raw_literal(expr: &Expr) -> Option<String> {
    match expr {
        Expr::Lit(lit) => match &lit.lit {
            Lit::Str(s) => {
                let v = s.value();
                if v.trim().is_empty() { None } else { Some(v) }
            }
            _ => None,
        },
        Expr::Reference(r) => extract_raw_literal(&r.expr),
        Expr::Group(g) => extract_raw_literal(&g.expr),
        Expr::Call(call) => {
            if let Expr::Path(ep) = call.func.as_ref() {
                let last = ep
                    .path
                    .segments
                    .last()
                    .map(|s| s.ident.to_string())
                    .unwrap_or_default();
                if matches!(last.as_str(), "new" | "from")
                    && let Some(arg) = call.args.first()
                {
                    return extract_raw_literal(arg);
                }
            }
            None
        }
        Expr::MethodCall(mc) => {
            let m = mc.method.to_string();
            match m.as_str() {
                "join" => {
                    let arg_lit = mc.args.first().and_then(extract_raw_literal)?;
                    if let Some(recv_lit) = extract_raw_literal(&mc.receiver) {
                        Some(format!(
                            "{}/{}",
                            recv_lit.trim().replace('\\', "/").trim_end_matches('/'),
                            arg_lit.trim().replace('\\', "/").trim_start_matches('/')
                        ))
                    } else {
                        Some(arg_lit)
                    }
                }
                "as_ref" | "as_path" | "as_str" | "to_string" | "to_owned" | "to_path_buf" => {
                    extract_raw_literal(&mc.receiver)
                }
                _ => None,
            }
        }
        _ => None,
    }
}

fn extract_format_write_prefix(fmt: &str) -> Option<String> {
    let prefix = fmt.split('{').next().unwrap_or("").trim();
    let norm = normalize_write_target(prefix)?;
    // Reject URL schemes (`https://`, `http://`, `file://`, etc.).
    if norm.contains("://") {
        return None;
    }
    // Reject bare trailing-slash single-segment directory or version prefixes like `"tmp/"`, `"data/"`, `"v1/"`.
    if norm.ends_with('/') {
        let stripped = norm.trim_end_matches('/');
        if !stripped.contains('/') {
            return None;
        }
    }
    Some(norm)
}

pub fn normalize_write_target(raw: &str) -> Option<String> {
    let normalized = raw.trim().replace('\\', "/");
    let stripped = normalized.trim_start_matches("./").trim();
    if stripped.len() < 2 || is_ephemeral_write_target(stripped) {
        return None;
    }
    if !stripped.chars().any(|c| c.is_ascii_alphanumeric()) {
        return None;
    }
    Some(stripped.to_string())
}

fn extract_path_attr(attrs: &[Attribute]) -> Option<(String, usize)> {
    for attr in attrs {
        if !attr.path().is_ident("path") {
            continue;
        }
        if let Meta::NameValue(nv) = &attr.meta
            && let Expr::Lit(lit) = &nv.value
            && let Lit::Str(s) = &lit.lit
        {
            return Some((s.value(), attr.span().start().line));
        }
    }
    None
}

fn normalize_rust_path_attr(raw: &str, mod_stack: &[String]) -> Option<String> {
    let normalized = raw.trim().replace('\\', "/");
    let stripped = normalized.trim_end_matches(".rs");
    let stripped = stripped.strip_suffix("/mod").unwrap_or(stripped);
    let mut parent_hops = 0usize;
    let mut rel_segs: Vec<String> = Vec::new();
    for seg in stripped.split('/') {
        match seg {
            "" | "." => {}
            ".." => {
                if !rel_segs.is_empty() {
                    rel_segs.pop();
                } else {
                    parent_hops += 1;
                }
            }
            other => rel_segs.push(other.to_string()),
        }
    }
    if rel_segs.is_empty() {
        return None;
    }

    let mut base: Vec<String> = mod_stack.to_vec();
    let mut leading_parents = 0usize;
    for _ in 0..parent_hops {
        if base.pop().is_none() {
            leading_parents += 1;
        }
    }

    let mut out: Vec<String> = Vec::new();
    if leading_parents > 0 {
        for _ in 0..leading_parents {
            out.push("..".to_string());
        }
    } else {
        out.push(".".to_string());
    }
    out.extend(base);
    out.extend(rel_segs);
    Some(out.join("/"))
}

fn measure_fn(
    name: String,
    param_count: usize,
    span: proc_macro2::Span,
    block: &Block,
) -> FunctionMetrics {
    let start_line = span.start().line;
    let end_line = span.end().line.max(start_line);
    let loc = end_line.saturating_sub(start_line) + 1;

    let mut depth_visitor = NestingVisitor::default();
    depth_visitor.visit_block(block);

    let is_flat_dispatcher = detect_flat_dispatcher(block, loc);

    FunctionMetrics {
        name,
        start_line,
        end_line,
        loc,
        param_count,
        max_nesting_depth: depth_visitor.max_depth,
        is_flat_dispatcher,
    }
}

fn detect_flat_dispatcher(block: &Block, fn_loc: usize) -> bool {
    let mut match_expr: Option<&syn::ExprMatch> = None;
    for stmt in &block.stmts {
        if let syn::Stmt::Expr(Expr::Match(m), _) = stmt {
            match_expr = Some(m);
        } else if let syn::Stmt::Expr(Expr::Return(ret), _) = stmt
            && let Some(expr) = &ret.expr
            && let Expr::Match(m) = expr.as_ref()
        {
            match_expr = Some(m);
        }
    }
    let Some(m) = match_expr else {
        return false;
    };
    if m.arms.len() < 8 {
        return false;
    }
    if fn_loc > m.arms.len().saturating_mul(5).saturating_add(24) {
        return false;
    }
    for arm in &m.arms {
        let mut arm_visitor = NestingVisitor::default();
        arm_visitor.visit_expr(&arm.body);
        if arm_visitor.max_depth > 2 {
            return false;
        }
    }
    true
}

#[derive(Default)]
struct NestingVisitor {
    current: usize,
    max_depth: usize,
}

impl NestingVisitor {
    fn enter<F: FnOnce(&mut Self)>(&mut self, f: F) {
        self.current += 1;
        if self.current > self.max_depth {
            self.max_depth = self.current;
        }
        f(self);
        self.current -= 1;
    }
}

impl<'ast> Visit<'ast> for NestingVisitor {
    fn visit_expr(&mut self, expr: &'ast Expr) {
        match expr {
            Expr::If(e) => {
                // Keep `else if` chains at the same logical nesting level as the outer `if`.
                self.enter(|v| {
                    v.visit_expr(&e.cond);
                    v.visit_block(&e.then_branch);
                });
                if let Some((_, else_branch)) = &e.else_branch {
                    match else_branch.as_ref() {
                        Expr::If(_) => self.visit_expr(else_branch),
                        other => self.enter(|v| v.visit_expr(other)),
                    }
                }
            }
            Expr::Match(_)
            | Expr::Loop(_)
            | Expr::While(_)
            | Expr::ForLoop(_)
            | Expr::Closure(_)
            | Expr::Async(_)
            | Expr::TryBlock(_) => {
                self.enter(|v| visit::visit_expr(v, expr));
            }
            _ => visit::visit_expr(self, expr),
        }
    }
}

fn is_data_literal_expr(expr: &Expr) -> bool {
    match expr {
        Expr::Array(_) | Expr::Repeat(_) | Expr::Tuple(_) => true,
        Expr::Reference(r) => is_data_literal_expr(&r.expr),
        Expr::Group(g) => is_data_literal_expr(&g.expr),
        _ => false,
    }
}

fn item_attrs(item: &Item) -> &[Attribute] {
    match item {
        Item::Const(x) => &x.attrs,
        Item::Enum(x) => &x.attrs,
        Item::ExternCrate(x) => &x.attrs,
        Item::Fn(x) => &x.attrs,
        Item::ForeignMod(x) => &x.attrs,
        Item::Impl(x) => &x.attrs,
        Item::Macro(x) => &x.attrs,
        Item::Mod(x) => &x.attrs,
        Item::Static(x) => &x.attrs,
        Item::Struct(x) => &x.attrs,
        Item::Trait(x) => &x.attrs,
        Item::TraitAlias(x) => &x.attrs,
        Item::Type(x) => &x.attrs,
        Item::Union(x) => &x.attrs,
        Item::Use(x) => &x.attrs,
        _ => &[],
    }
}

/// Returns true ONLY when a `#[cfg(...)]` predicate unambiguously gates an item to
/// test builds (`cfg(test)` or positive `cfg(all(..., test, ...))`), and explicitly
/// returns false inside `cfg(not(...))` or `cfg(any(...))`.
fn has_test_cfg(attrs: &[Attribute]) -> bool {
    attrs.iter().any(|attr| {
        if !attr.path().is_ident("cfg") {
            return false;
        }
        let Ok(nested) = attr.parse_args_with(Punctuated::<Meta, Token![,]>::parse_terminated)
        else {
            return false;
        };
        nested.len() == 1 && cfg_meta_requires_test(&nested[0])
    })
}

fn cfg_meta_requires_test(meta: &Meta) -> bool {
    match meta {
        Meta::Path(path) => path.is_ident("test"),
        Meta::List(list) => {
            if list.path.is_ident("not") || list.path.is_ident("any") {
                return false;
            }
            if list.path.is_ident("all") {
                let Ok(items) =
                    list.parse_args_with(Punctuated::<Meta, Token![,]>::parse_terminated)
                else {
                    return false;
                };
                return items.iter().any(cfg_meta_requires_test);
            }
            false
        }
        Meta::NameValue(_) => false,
    }
}

fn has_test_attr(attrs: &[Attribute]) -> bool {
    attrs.iter().any(|attr| {
        attr.path().is_ident("test")
            || attr
                .path()
                .segments
                .last()
                .is_some_and(|seg| seg.ident == "test")
    })
}

fn collect_suppressions(
    attrs: &[Attribute],
    lines: &[&str],
    out: &mut SuppressionMetrics,
    file_scope: bool,
) {
    for attr in attrs {
        if !attr.path().is_ident("allow") {
            continue;
        }
        let is_inner = matches!(attr.style, syn::AttrStyle::Inner(_));
        let args = match &attr.meta {
            Meta::List(list) => list.tokens.to_string(),
            _ => String::new(),
        };
        let compact: String = args.chars().filter(|c| !c.is_whitespace()).collect();
        let is_blanket = is_inner
            || file_scope
            || compact.contains("warnings")
            || compact.contains("clippy::all")
            || compact.contains("clippy::pedantic")
            || compact.contains("clippy::nursery");

        out.total += 1;
        if is_blanket {
            out.blanket += 1;
        } else {
            out.narrow += 1;
            let line = attr.span().start().line;
            if has_preceding_comment(lines, line) {
                out.justified_narrow += 1;
            }
        }
        let prefix = if is_inner { "#![allow(" } else { "#[allow(" };
        if out.directives.len() < 32 {
            out.directives.push(format!("{prefix}{compact})]"));
        }
    }
}

pub fn has_preceding_comment(lines: &[&str], one_based_line: usize) -> bool {
    if one_based_line <= 1 || lines.is_empty() {
        return false;
    }
    let idx = one_based_line.saturating_sub(2);
    let start = idx.saturating_sub(3);
    for i in (start..=idx).rev() {
        let Some(raw) = lines.get(i) else { continue };
        let trimmed = raw.trim();
        if trimmed.is_empty() {
            break;
        }
        if trimmed.starts_with("//")
            || trimmed.starts_with("/*")
            || trimmed.starts_with('*')
            || trimmed.starts_with('#')
        {
            if trimmed.starts_with("#[") {
                continue;
            }
            return true;
        }
        break;
    }
    false
}

fn extract_internal_use(
    tree: &UseTree,
    prefix: Vec<String>,
    line: usize,
    out: &mut BTreeSet<String>,
    paths: &mut BTreeSet<String>,
    reach_ins: &mut Vec<ReachInSignal>,
) {
    match tree {
        UseTree::Path(path) => {
            let mut next = prefix;
            next.push(path.ident.to_string());
            extract_internal_use(&path.tree, next, line, out, paths, reach_ins);
        }
        UseTree::Group(group) => {
            for item in &group.items {
                extract_internal_use(item, prefix.clone(), line, out, paths, reach_ins);
            }
        }
        UseTree::Name(name) => {
            let mut full = prefix;
            full.push(name.ident.to_string());
            record_internal_path(&full, line, out, paths, reach_ins);
        }
        UseTree::Rename(rename) => {
            let mut full = prefix;
            full.push(rename.ident.to_string());
            record_internal_path(&full, line, out, paths, reach_ins);
        }
        UseTree::Glob(_) => {
            record_internal_path(&prefix, line, out, paths, reach_ins);
        }
    }
}

fn record_internal_path(
    segments: &[String],
    line: usize,
    out: &mut BTreeSet<String>,
    paths: &mut BTreeSet<String>,
    reach_ins: &mut Vec<ReachInSignal>,
) {
    let Some(first) = segments.first() else {
        return;
    };
    if first != "crate" && first != "super" && first != "self" {
        return;
    }
    let tail = &segments[1..];
    if tail.is_empty() {
        return;
    }

    // Preserve the full anchored internal path (`crate/...`, `super/...`, `self/...`)
    // so `graph_topology` can resolve the exact longest-prefix submodule file without
    // polluting parent `mod.rs` containers with false edges.
    paths.insert(segments.join("/"));

    // Collect non-keyword segments for fallback stem matching & reach-in inspection.
    let mod_segs: Vec<&str> = tail
        .iter()
        .map(String::as_str)
        .filter(|s| *s != "super" && *s != "self")
        .collect();
    if mod_segs.is_empty() {
        return;
    }

    let snake_segs: Vec<&str> = mod_segs
        .iter()
        .copied()
        .take_while(|s| is_snake_or_private_mod(s))
        .collect();
    if let Some(leaf_mod) = snake_segs.last() {
        out.insert((*leaf_mod).to_string());
    } else if let Some(first_mod) = mod_segs.first() {
        out.insert((*first_mod).to_string());
    }

    // Detect cross-boundary reach-ins into private (`_...`) or deep `internal`/`private`/`detail` submodules.
    if reach_ins.len() < MAX_REACH_INS_PER_FILE {
        let joined = segments.join("::");
        let has_private_seg = mod_segs.iter().any(|s| is_private_ident(s));
        let has_deep_internal = mod_segs.len() >= 2
            && mod_segs
                .iter()
                .any(|s| matches!(*s, "internal" | "private" | "detail"));
        if has_private_seg {
            reach_ins.push(ReachInSignal {
                kind: "rust_private_reach_in".to_string(),
                target: joined,
                line,
            });
        } else if has_deep_internal {
            reach_ins.push(ReachInSignal {
                kind: "rust_deep_internal_import".to_string(),
                target: joined,
                line,
            });
        }
    }
}

pub fn is_private_ident(seg: &str) -> bool {
    seg.starts_with('_') && seg.len() > 1 && !(seg.starts_with("__") && seg.ends_with("__"))
}

fn is_snake_or_private_mod(seg: &str) -> bool {
    seg.chars()
        .next()
        .is_some_and(|c| c.is_ascii_lowercase() || c == '_')
}

fn merged_line_count(ranges: &[(usize, usize)], total_lines: usize) -> usize {
    if ranges.is_empty() {
        return 0;
    }
    let mut sorted: Vec<(usize, usize)> = ranges
        .iter()
        .filter_map(|&(s, e)| {
            if s == 0 || e < s {
                None
            } else {
                Some((s.min(total_lines), e.min(total_lines)))
            }
        })
        .collect();
    if sorted.is_empty() {
        return 0;
    }
    sorted.sort_unstable();
    let mut merged: Vec<(usize, usize)> = Vec::new();
    for (s, e) in sorted {
        if let Some(last) = merged.last_mut()
            && s <= last.1 + 1
        {
            last.1 = last.1.max(e);
        } else {
            merged.push((s, e));
        }
    }
    merged.into_iter().map(|(s, e)| e - s + 1).sum()
}

fn strip_line_ranges(lines: &[&str], ranges: &[(usize, usize)]) -> String {
    let mut out = String::new();
    for (idx, line) in lines.iter().enumerate() {
        let ln = idx + 1;
        let in_test = ranges.iter().any(|&(s, e)| ln >= s && ln <= e);
        if !in_test {
            out.push_str(line);
            out.push('\n');
        }
    }
    out
}

pub fn estimate_tokens(text: &str) -> usize {
    let mut tokens = 0usize;
    let mut in_word = false;
    for ch in text.chars() {
        if ch.is_alphanumeric() || ch == '_' {
            if !in_word {
                tokens += 1;
                in_word = true;
            }
        } else {
            in_word = false;
            if !ch.is_whitespace() {
                tokens += 1;
            }
        }
    }
    tokens
}
