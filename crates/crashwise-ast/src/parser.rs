use crate::types::*;
use crashwise_core::error::{CrashwiseError, Result};
use std::path::Path;
use tree_sitter::{Node, Parser};

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

    pub fn parse_file(&mut self, path: &Path) -> Result<Vec<FunctionSignature>> {
        let content = std::fs::read_to_string(path)?;
        let is_cpp = path.extension().map_or(false, |ext| {
            ext == "cpp" || ext == "cc" || ext == "cxx" || ext == "hpp"
        });

        let tree = if is_cpp {
            self.cpp_parser.parse(&content, None)
        } else {
            self.c_parser.parse(&content, None)
        };

        let tree = tree.ok_or_else(|| CrashwiseError::AstError(format!("Failed to parse {}", path.display())))?;
        let root = tree.root_node();

        let mut functions = Vec::new();
        self.extract_functions(&root, &content, path, &mut functions);
        Ok(functions)
    }

    fn extract_functions(&self, node: &Node, content: &str, file_path: &Path, functions: &mut Vec<FunctionSignature>) {
        if node.kind() == "function_definition" || node.kind() == "declaration" {
            if let Some(func) = self.parse_function_node(node, content, file_path) {
                functions.push(func);
            }
        }

        let mut cursor = node.walk();
        for child in node.children(&mut cursor) {
            self.extract_functions(&child, content, file_path, functions);
        }
    }

    fn parse_function_node(&self, node: &Node, content: &str, file_path: &Path) -> Option<FunctionSignature> {
        let declarator = node.child_by_field_name("declarator")?;
        let (func_name, params) = self.extract_declarator_info(&declarator, content)?;

        let return_type = node
            .child_by_field_name("type")
            .map(|t| t.utf8_text(content.as_bytes()).unwrap_or("void").to_string())
            .unwrap_or_else(|| "int".to_string());

        let has_body = node.child_by_field_name("body").is_some();
        let is_static = content[node.byte_range()].contains("static ");

        Some(FunctionSignature {
            name: func_name,
            return_type,
            parameters: params,
            file_path: file_path.to_path_buf(),
            line_number: node.start_position().row + 1,
            is_static,
            is_exported: !is_static && has_body,
            has_body,
        })
    }

    fn extract_declarator_info(&self, node: &Node, content: &str) -> Option<(String, Vec<ParameterInfo>)> {
        if node.kind() == "function_declarator" {
            let direct_decl = node.child_by_field_name("declarator")?;
            let name = direct_decl.utf8_text(content.as_bytes()).ok()?.to_string();

            let mut params = Vec::new();
            if let Some(param_list) = node.child_by_field_name("parameters") {
                let mut cursor = param_list.walk();
                for param in param_list.children(&mut cursor) {
                    if param.kind() == "parameter_declaration" {
                        let p_type = param
                            .child_by_field_name("type")
                            .map(|t| t.utf8_text(content.as_bytes()).unwrap_or("void*").to_string())
                            .unwrap_or_else(|| "void*".to_string());

                        let p_name = param
                            .child_by_field_name("declarator")
                            .map(|d| d.utf8_text(content.as_bytes()).unwrap_or("param").to_string())
                            .unwrap_or_else(|| "param".to_string());

                        let is_pointer = p_type.contains('*') || p_name.contains('*');
                        let is_const = p_type.contains("const ");

                        params.push(ParameterInfo {
                            name: p_name.trim_start_matches('*').to_string(),
                            type_name: p_type,
                            is_pointer,
                            is_const,
                        });
                    }
                }
            }
            return Some((name, params));
        }
        None
    }
}

pub fn scan_directory_ast(dir: &Path) -> Result<TargetAstProfile> {
    let mut parser = AstParser::new()?;
    let mut all_functions = Vec::new();
    let mut public_headers = Vec::new();

    for entry in walkdir::WalkDir::new(dir)
        .into_iter()
        .filter_map(|e| e.ok())
        .filter(|e| e.file_type().is_file())
    {
        let path = entry.path();
        if let Some(ext) = path.extension() {
            if ext == "c" || ext == "cpp" || ext == "cc" || ext == "h" || ext == "hpp" {
                if ext == "h" || ext == "hpp" {
                    public_headers.push(path.to_path_buf());
                }
                if let Ok(funcs) = parser.parse_file(path) {
                    all_functions.extend(funcs);
                }
            }
        }
    }

    Ok(TargetAstProfile {
        functions: all_functions,
        structs: Vec::new(),
        dangerous_sinks: Vec::new(),
        public_headers,
    })
}
