use crate::callgraph::CallgraphAnalyzer;
use crate::layout::StructLayoutResolver;
use crate::types::*;
use crashwise_core::error::{CrashwiseError, Result};
use std::collections::{HashMap, HashSet};
use std::path::Path;
use tree_sitter::{Node, Parser, Tree};

pub struct AstParser {
    c_parser: Parser,
    cpp_parser: Parser,
}

impl Default for AstParser {
    fn default() -> Self {
        Self::new().expect("Failed to initialize tree-sitter parsers")
    }
}

impl AstParser {
    pub fn new() -> Result<Self> {
        let mut c_parser = Parser::new();
        c_parser
            .set_language(&tree_sitter_c::language())
            .map_err(|e| CrashwiseError::AstError(format!("Failed to load C grammar: {e}")))?;

        let mut cpp_parser = Parser::new();
        cpp_parser
            .set_language(&tree_sitter_cpp::language())
            .map_err(|e| CrashwiseError::AstError(format!("Failed to load C++ grammar: {e}")))?;

        Ok(Self {
            c_parser,
            cpp_parser,
        })
    }

    pub fn parse_source(&mut self, content: &str, path: &Path) -> Result<Vec<FunctionSignature>> {
        let tree = self.parse_content(content, path)?;
        let root = tree.root_node();

        let is_header = path
            .extension()
            .is_some_and(|ext| ext == "h" || ext == "hpp");

        let mut functions = Vec::new();
        self.extract_functions(&root, content, path, is_header, &mut functions);
        Ok(functions)
    }

    pub fn parse_file(&mut self, path: &Path) -> Result<Vec<FunctionSignature>> {
        let content = std::fs::read_to_string(path)?;
        self.parse_source(&content, path)
    }


    pub fn parse_content(&mut self, content: &str, path: &Path) -> Result<Tree> {
        let is_cpp = path.extension().is_some_and(|ext| {
            ext == "cpp" || ext == "cc" || ext == "cxx" || ext == "hpp"
        });

        let tree = if is_cpp {
            self.cpp_parser.parse(content, None)
        } else {
            self.c_parser.parse(content, None)
        };

        tree.ok_or_else(|| CrashwiseError::AstError(format!("Failed to parse {}", path.display())))
    }

    pub fn resolve_struct_layouts(
        &self,
        tree: &Tree,
        source: &str,
        file_path: &Path,
    ) -> Result<TypeLayoutGraph> {
        let mut resolver = StructLayoutResolver::new();
        resolver.resolve_struct_layouts(tree, source, file_path)
    }

    fn extract_functions(
        &self,
        node: &Node,
        content: &str,
        file_path: &Path,
        is_header: bool,
        functions: &mut Vec<FunctionSignature>,
    ) {
        let kind = node.kind();
        if kind == "function_definition" || kind == "declaration" {
            if let Some(func) = self.parse_function_node(node, content, file_path, is_header) {
                functions.push(func);
            }
        }

        let mut cursor = node.walk();
        for child in node.children(&mut cursor) {
            self.extract_functions(&child, content, file_path, is_header, functions);
        }
    }

    fn parse_function_node(
        &self,
        node: &Node,
        content: &str,
        file_path: &Path,
        is_header: bool,
    ) -> Option<FunctionSignature> {
        let declarator = node.child_by_field_name("declarator")?;
        let (func_name, params) = self.extract_declarator_info(&declarator, content)?;

        let return_type = node
            .child_by_field_name("type")
            .and_then(|t| t.utf8_text(content.as_bytes()).ok())
            .unwrap_or("int")
            .to_string();

        let has_body = node.child_by_field_name("body").is_some();

        // Pure Tree-sitter AST queries for storage class specifiers (no regex or string matching)
        let is_static = self.is_node_static(node, content);
        let is_extern = self.is_node_extern(node, content);

        // Exported logic:
        // 1. If static: never exported.
        // 2. In public headers: non-static declarations are public exported interface.
        // 3. In source files: non-static function definitions or extern declarations are exported.
        let is_exported = !is_static && (is_header || has_body || is_extern);

        Some(FunctionSignature {
            name: func_name,
            return_type,
            parameters: params,
            file_path: file_path.to_path_buf(),
            line_number: node.start_position().row + 1,
            is_static,
            is_exported,
            has_body,
        })
    }

    fn is_node_static(&self, node: &Node, content: &str) -> bool {
        let mut cursor = node.walk();
        for child in node.children(&mut cursor) {
            if child.kind() == "storage_class_specifier" {
                if let Ok(text) = child.utf8_text(content.as_bytes()) {
                    if text.trim() == "static" {
                        return true;
                    }
                }
            }
        }
        false
    }

    fn is_node_extern(&self, node: &Node, content: &str) -> bool {
        let mut cursor = node.walk();
        for child in node.children(&mut cursor) {
            if child.kind() == "storage_class_specifier" {
                if let Ok(text) = child.utf8_text(content.as_bytes()) {
                    if text.trim() == "extern" {
                        return true;
                    }
                }
            }
        }
        false
    }

    fn extract_declarator_info(
        &self,
        node: &Node,
        content: &str,
    ) -> Option<(String, Vec<ParameterInfo>)> {
        if node.kind() == "function_declarator" {
            let direct_decl = node.child_by_field_name("declarator")?;
            let name = self.extract_name_from_declarator(&direct_decl, content)?;

            let mut params = Vec::new();
            if let Some(param_list) = node.child_by_field_name("parameters") {
                let mut cursor = param_list.walk();
                for param in param_list.children(&mut cursor) {
                    if param.kind() == "parameter_declaration" {
                        let p_type = param
                            .child_by_field_name("type")
                            .and_then(|t| t.utf8_text(content.as_bytes()).ok())
                            .unwrap_or("void*")
                            .to_string();

                        // Pure AST queries for type qualifier and pointer declarator
                        let mut is_const = false;
                        let mut is_pointer = false;
                        let mut p_name = String::new();

                        let mut p_cursor = param.walk();
                        for p_child in param.children(&mut p_cursor) {
                            if p_child.kind() == "type_qualifier" {
                                if let Ok(q) = p_child.utf8_text(content.as_bytes()) {
                                    if q.trim() == "const" {
                                        is_const = true;
                                    }
                                }
                            } else if p_child.kind() == "pointer_declarator" {
                                is_pointer = true;
                                if let Some(inner) = self.extract_identifier_from_pointer(&p_child, content) {
                                    p_name = inner;
                                }
                            } else if p_child.kind() == "identifier" {
                                p_name = p_child.utf8_text(content.as_bytes()).unwrap_or("").to_string();
                            }
                        }

                        if let Some(decl) = param.child_by_field_name("declarator") {
                            if decl.kind() == "pointer_declarator" {
                                is_pointer = true;
                            }
                            if p_name.is_empty() {
                                if let Some(n) = self.extract_name_from_declarator(&decl, content) {
                                    p_name = n;
                                }
                            }
                        }

                        params.push(ParameterInfo {
                            name: p_name,
                            type_name: p_type,
                            is_pointer,
                            is_const,
                        });
                    }
                }
            }
            return Some((name, params));
        } else if node.kind() == "pointer_declarator" {
            if let Some(inner) = node.child_by_field_name("declarator") {
                return self.extract_declarator_info(&inner, content);
            }
        }
        None
    }

    fn extract_name_from_declarator(&self, node: &Node, content: &str) -> Option<String> {
        match node.kind() {
            "identifier" | "field_identifier" => {
                node.utf8_text(content.as_bytes()).ok().map(|s| s.to_string())
            }
            "pointer_declarator" => {
                let inner = node.child_by_field_name("declarator")?;
                self.extract_name_from_declarator(&inner, content)
            }
            "parenthesized_declarator" => {
                let mut cursor = node.walk();
                for child in node.children(&mut cursor) {
                    if child.kind() != "(" && child.kind() != ")" {
                        if let Some(name) = self.extract_name_from_declarator(&child, content) {
                            return Some(name);
                        }
                    }
                }
                None
            }
            "function_declarator" => {
                let inner = node.child_by_field_name("declarator")?;
                self.extract_name_from_declarator(&inner, content)
            }
            _ => node.utf8_text(content.as_bytes()).ok().map(|s| s.to_string()),
        }
    }

    fn extract_identifier_from_pointer(&self, node: &Node, content: &str) -> Option<String> {
        let mut curr = *node;
        while curr.kind() == "pointer_declarator" {
            let inner = curr.child_by_field_name("declarator")?;
            curr = inner;
        }
        if curr.kind() == "identifier" || curr.kind() == "field_identifier" {
            return curr.utf8_text(content.as_bytes()).ok().map(|s| s.to_string());
        }
        None
    }
}

pub fn scan_directory_ast(dir: &Path) -> Result<TargetAstProfile> {
    let mut parser = AstParser::new()?;
    let mut resolver = StructLayoutResolver::new();
    let mut callgraph_analyzer = CallgraphAnalyzer::new();

    let mut all_functions = Vec::new();
    let mut public_headers = Vec::new();
    let mut source_files = Vec::new();
    let mut all_dangerous_sinks = Vec::new();
    let mut header_declared_funcs: HashSet<String> = HashSet::new();

    // 1. Gather all files
    for entry in walkdir::WalkDir::new(dir)
        .into_iter()
        .filter_map(|e| e.ok())
        .filter(|e| e.file_type().is_file())
    {
        let path = entry.path();
        if let Some(ext) = path.extension().and_then(|e| e.to_str()) {
            if ext == "h" || ext == "hpp" {
                public_headers.push(path.to_path_buf());
            } else if ext == "c" || ext == "cpp" || ext == "cc" || ext == "cxx" {
                source_files.push(path.to_path_buf());
            }
        }
    }

    // Sort paths for deterministic AST processing
    public_headers.sort();
    source_files.sort();

    // 2. Parse public headers first to resolve exported declarations and header types
    for h_path in &public_headers {
        if let Ok(content) = std::fs::read_to_string(h_path) {
            if let Ok(tree) = parser.parse_content(&content, h_path) {
                // Layout resolution in header
                let _ = resolver.resolve_struct_layouts(&tree, &content, h_path);

                // Extract function signatures in header
                if let Ok(funcs) = parser.parse_file(h_path) {
                    for f in &funcs {
                        if !f.is_static {
                            header_declared_funcs.insert(f.name.clone());
                        }
                    }
                    all_functions.extend(funcs);
                }
            }
        }
    }

    // 3. Parse source files (.c, .cpp)
    for s_path in &source_files {
        if let Ok(content) = std::fs::read_to_string(s_path) {
            if let Ok(tree) = parser.parse_content(&content, s_path) {
                // Layout resolution in source
                let _ = resolver.resolve_struct_layouts(&tree, &content, s_path);

                // Functions in source
                if let Ok(mut funcs) = parser.parse_file(s_path) {
                    for f in &mut funcs {
                        // If function matches a public header prototype, mark as exported
                        if header_declared_funcs.contains(&f.name) {
                            f.is_exported = true;
                        }
                    }
                    all_functions.extend(funcs);
                }

                // Extract dangerous sinks and callgraph
                let (_, sinks) = callgraph_analyzer.extract_calls_and_sinks(s_path, &content);
                all_dangerous_sinks.extend(sinks);
            }
        }
    }

    // 4. Construct cumulative TypeLayoutGraph and StructInfo collection
    let mut layout_graph = TypeLayoutGraph::new();
    layout_graph.structs = resolver.known_structs.clone();
    layout_graph.unions = resolver.known_unions.clone();
    layout_graph.typedefs = resolver.known_typedefs.clone();

    // Deduplicate structs into StructInfo models
    let mut structs = Vec::new();
    let mut seen_struct_tags = HashSet::new();

    for (name, s_layout) in &resolver.known_structs {
        // Only include non-prefixed struct names to avoid duplicating "struct Foo" and "Foo"
        if name.starts_with("struct ") {
            continue;
        }

        let key = format!("{}:{}", s_layout.file_path.display(), s_layout.line_number);
        if seen_struct_tags.insert(key) {
            let fields = s_layout
                .fields
                .iter()
                .map(|f| StructFieldInfo {
                    name: f.name.clone(),
                    type_name: match &f.type_kind {
                        TypeKind::Primitive { name, .. } => name.clone(),
                        TypeKind::Pointer { pointee, indirection, .. } => {
                            let p_str = match &**pointee {
                                TypeKind::Primitive { name, .. } => name.as_str(),
                                TypeKind::StructRef { name } => name.as_str(),
                                TypeKind::UnionRef { name } => name.as_str(),
                                _ => "void",
                            };
                            format!("{}{}", p_str, "*".repeat(*indirection))
                        }
                        TypeKind::StructRef { name } => format!("struct {name}"),
                        TypeKind::UnionRef { name } => format!("union {name}"),
                        TypeKind::Array { element, len } => {
                            let el_str = match &**element {
                                TypeKind::Primitive { name, .. } => name.as_str(),
                                _ => "element",
                            };
                            format!("{}[{}]", el_str, len.unwrap_or(0))
                        }
                        _ => "unknown".to_string(),
                    },
                    offset_bytes: f.offset_bytes,
                    size_bytes: f.size_bytes,
                    align_bytes: f.align_bytes,
                })
                .collect();

            structs.push(StructInfo {
                name: s_layout.name.clone().unwrap_or_else(|| name.clone()),
                fields,
                file_path: s_layout.file_path.clone(),
                line_number: s_layout.line_number,
                total_size_bytes: s_layout.total_size_bytes,
                align_bytes: s_layout.align_bytes,
            });
        }
    }

    // Sort structs by file_path and line_number
    structs.sort_by(|a, b| a.name.cmp(&b.name));

    // Populate field offsets in layout_graph
    for (name, s_layout) in &resolver.known_structs {
        let mut field_map = HashMap::new();
        for f in &s_layout.fields {
            field_map.insert(f.name.clone(), f.offset_bytes);
        }
        layout_graph.field_offsets.insert(name.clone(), field_map);
    }

    for (name, u_layout) in &resolver.known_unions {
        let mut field_map = HashMap::new();
        for v in &u_layout.variants {
            field_map.insert(v.name.clone(), 0);
        }
        layout_graph.field_offsets.insert(name.clone(), field_map);
    }

    Ok(TargetAstProfile {
        functions: all_functions,
        structs,
        dangerous_sinks: all_dangerous_sinks,
        public_headers,
        layout_graph: Some(layout_graph),
    })
}
