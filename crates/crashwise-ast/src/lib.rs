pub mod callgraph;
pub mod lifecycle;
pub mod parser;
pub mod types;

pub use callgraph::CallgraphAnalyzer;
pub use lifecycle::{LifecycleMiner, StatefulSequence};
pub use parser::{scan_directory_ast, AstParser};
pub use types::*;

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;
    use tempfile::NamedTempFile;

    #[test]
    fn test_tree_sitter_c_parser() {
        let mut file = NamedTempFile::new().unwrap();
        writeln!(
            file,
            "int parse_png_header(const uint8_t *data, size_t size) {{\n    return 0;\n}}\n\nstatic void helper() {{}}"
        )
        .unwrap();

        let mut parser = AstParser::new().unwrap();
        let funcs = parser.parse_file(file.path()).unwrap();

        assert_eq!(funcs.len(), 2);
        assert_eq!(funcs[0].name, "parse_png_header");
        assert_eq!(funcs[0].parameters.len(), 2);
        assert_eq!(funcs[0].is_static, false);
        assert_eq!(funcs[0].is_exported, true);

        assert_eq!(funcs[1].name, "helper");
        assert_eq!(funcs[1].is_static, true);
    }

    #[test]
    fn test_callgraph_and_sinks() {
        let code = r#"
        void vulnerable(const char *src) {
            char buf[64];
            strcpy(buf, src);
        }
        void caller(const char *input) {
            vulnerable(input);
        }
        "#;
        let mut analyzer = CallgraphAnalyzer::new();
        let (calls, sinks) = analyzer.extract_calls_and_sinks(std::path::Path::new("test.c"), code);

        assert_eq!(sinks.len(), 1);
        assert_eq!(sinks[0].sink_type, "strcpy");
        assert_eq!(sinks[0].function_name, "vulnerable");

        let reachability = CallgraphAnalyzer::compute_reachability(&calls, &sinks);
        assert_eq!(reachability.get("caller").copied(), Some(1));
    }
}
