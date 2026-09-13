#![allow(clippy::for_kv_map)]

pub mod callgraph;
pub mod layout;
pub mod lifecycle;
pub mod parser;
pub mod types;

pub use callgraph::CallgraphAnalyzer;
pub use layout::{primitive_layout, StructLayoutResolver};
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
        assert!(!funcs[0].is_static);
        assert!(funcs[0].is_exported);

        assert_eq!(funcs[1].name, "helper");
        assert!(funcs[1].is_static);
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

    #[test]
    fn test_packed_struct_layout() {
        let code = r#"
        struct __attribute__((packed)) PackedHeader {
            char tag;
            int value;
            short flag;
        };
        "#;
        let mut parser = AstParser::new().unwrap();
        let tree = parser.parse_content(code, std::path::Path::new("packed.c")).unwrap();
        let graph = parser.resolve_struct_layouts(&tree, code, std::path::Path::new("packed.c")).unwrap();

        let packed = graph.get_struct("PackedHeader").expect("PackedHeader not found");
        assert!(packed.is_packed);
        // With packed attribute: no alignment padding between fields
        assert_eq!(packed.fields[0].offset_bytes, 0); // tag
        assert_eq!(packed.fields[1].offset_bytes, 1); // value
        assert_eq!(packed.fields[2].offset_bytes, 5); // flag
        assert_eq!(packed.total_size_bytes, 7);
        assert_eq!(packed.align_bytes, 1);
    }

    #[test]
    fn test_ast_parser_resolve_struct_layouts() {
        let code = r#"
        struct Vector3D {
            double x;
            double y;
            double z;
        };
        "#;
        let mut parser = AstParser::new().unwrap();
        let tree = parser.parse_content(code, std::path::Path::new("vec.c")).unwrap();
        let graph = parser.resolve_struct_layouts(&tree, code, std::path::Path::new("vec.c")).unwrap();

        let vec_struct = graph.get_struct("Vector3D").expect("Vector3D not found");
        assert_eq!(vec_struct.total_size_bytes, 24);
        assert_eq!(vec_struct.align_bytes, 8);
        assert_eq!(graph.get_field_offset("Vector3D", "x"), Some(0));
        assert_eq!(graph.get_field_offset("Vector3D", "y"), Some(8));
        assert_eq!(graph.get_field_offset("Vector3D", "z"), Some(16));
    }

    #[test]
    fn test_pointer_return_function() {
        let mut parser = AstParser::new().unwrap();
        let header_code = r#"
        #ifndef CJSON_H
        #define CJSON_H
        extern int cJSON_Parse(const char *value);
        extern char *cJSON_Print(const void *item);
        extern void cJSON_Delete(void *c);
        #endif
        "#;
        let funcs = parser
            .parse_source(header_code, std::path::Path::new("test.h"))
            .unwrap();
        assert_eq!(funcs.len(), 3);
        assert_eq!(funcs[0].name, "cJSON_Parse");
        assert_eq!(funcs[1].name, "cJSON_Print");
        assert_eq!(funcs[2].name, "cJSON_Delete");
    }
}



