use crate::types::*;
use std::collections::{HashMap, HashSet};
use std::path::Path;
use tree_sitter::{Node, Parser};

pub struct CallgraphAnalyzer {
    parser: Parser,
}

impl Default for CallgraphAnalyzer {
    fn default() -> Self {
        let mut parser = Parser::new();
        parser
            .set_language(&tree_sitter_c::language())
            .expect("Failed to load C grammar");
        Self { parser }
    }
}

impl CallgraphAnalyzer {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn extract_calls_and_sinks(
        &mut self,
        path: &Path,
        content: &str,
    ) -> (HashMap<String, Vec<String>>, Vec<DangerousSink>) {
        let mut call_map: HashMap<String, Vec<String>> = HashMap::new();
        let mut sinks: Vec<DangerousSink> = Vec::new();

        let tree = match self.parser.parse(content, None) {
            Some(t) => t,
            None => return (call_map, sinks),
        };

        let root = tree.root_node();
        let mut cursor = root.walk();

        for child in root.children(&mut cursor) {
            if child.kind() == "function_definition" {
                if let Some(func_name) = self.get_function_name(&child, content) {
                    let mut called_funcs = Vec::new();
                    self.traverse_function_body(&child, content, path, &func_name, &mut called_funcs, &mut sinks);
                    call_map.insert(func_name, called_funcs);
                }
            }
        }

        (call_map, sinks)
    }

    fn get_function_name(&self, node: &Node, content: &str) -> Option<String> {
        let declarator = node.child_by_field_name("declarator")?;
        self.extract_name_from_declarator(&declarator, content)
    }

    fn extract_name_from_declarator(&self, node: &Node, content: &str) -> Option<String> {
        if node.kind() == "identifier" {
            return Some(node.utf8_text(content.as_bytes()).ok()?.to_string());
        }
        if node.kind() == "function_declarator" {
            let inner = node.child_by_field_name("declarator")?;
            return self.extract_name_from_declarator(&inner, content);
        }
        if node.kind() == "pointer_declarator" {
            let mut cursor = node.walk();
            for child in node.children(&mut cursor) {
                if let Some(name) = self.extract_name_from_declarator(&child, content) {
                    return Some(name);
                }
            }
        }
        None
    }

    fn traverse_function_body(
        &self,
        node: &Node,
        content: &str,
        path: &Path,
        current_func: &str,
        called_funcs: &mut Vec<String>,
        sinks: &mut Vec<DangerousSink>,
    ) {
        if node.kind() == "call_expression" {
            if let Some(function_node) = node.child_by_field_name("function") {
                if let Ok(callee_name) = function_node.utf8_text(content.as_bytes()) {
                    let callee = callee_name.to_string();
                    called_funcs.push(callee.clone());

                    if Self::is_dangerous_sink(&callee) {
                        sinks.push(DangerousSink {
                            function_name: current_func.to_string(),
                            sink_type: callee,
                            file_path: path.to_path_buf(),
                            line_number: node.start_position().row + 1,
                            caller: Some(current_func.to_string()),
                        });
                    }
                }
            }
        }

        let mut cursor = node.walk();
        for child in node.children(&mut cursor) {
            self.traverse_function_body(&child, content, path, current_func, called_funcs, sinks);
        }
    }

    fn is_dangerous_sink(callee: &str) -> bool {
        matches!(
            callee,
            "memcpy"
                | "memmove"
                | "strcpy"
                | "strncpy"
                | "strcat"
                | "strncat"
                | "sprintf"
                | "vsprintf"
                | "gets"
                | "malloc"
                | "calloc"
                | "realloc"
                | "free"
                | "read"
                | "recv"
                | "system"
                | "execve"
                | "popen"
        )
    }

    pub fn compute_reachability(
        call_map: &HashMap<String, Vec<String>>,
        sinks: &[DangerousSink],
    ) -> HashMap<String, usize> {
        let mut sink_func_names: HashSet<String> = HashSet::new();
        for sink in sinks {
            sink_func_names.insert(sink.function_name.clone());
        }

        let mut scores: HashMap<String, usize> = HashMap::new();

        for (caller, _) in call_map {
            let mut visited = HashSet::new();
            let mut queue = vec![caller.clone()];
            let mut sink_count = 0;

            while let Some(current) = queue.pop() {
                if visited.contains(&current) {
                    continue;
                }
                visited.insert(current.clone());

                if sink_func_names.contains(&current) {
                    sink_count += 1;
                }

                if let Some(callees) = call_map.get(&current) {
                    for c in callees {
                        if !visited.contains(c) {
                            queue.push(c.clone());
                        }
                    }
                }
            }

            scores.insert(caller.clone(), sink_count);
        }

        scores
    }
}
