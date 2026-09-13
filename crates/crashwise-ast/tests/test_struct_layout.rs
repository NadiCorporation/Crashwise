use crashwise_ast::{
    primitive_layout, scan_directory_ast, AstParser, StructLayoutResolver, TypeKind,
};
use std::path::Path;


#[test]
fn test_system_v_amd64_primitive_layouts() {
    assert_eq!(primitive_layout("char"), Some((1, 1)));
    assert_eq!(primitive_layout("signed char"), Some((1, 1)));
    assert_eq!(primitive_layout("unsigned char"), Some((1, 1)));
    assert_eq!(primitive_layout("uint8_t"), Some((1, 1)));

    assert_eq!(primitive_layout("short"), Some((2, 2)));
    assert_eq!(primitive_layout("unsigned short"), Some((2, 2)));
    assert_eq!(primitive_layout("int16_t"), Some((2, 2)));

    assert_eq!(primitive_layout("int"), Some((4, 4)));
    assert_eq!(primitive_layout("unsigned int"), Some((4, 4)));
    assert_eq!(primitive_layout("float"), Some((4, 4)));
    assert_eq!(primitive_layout("int32_t"), Some((4, 4)));

    assert_eq!(primitive_layout("long"), Some((8, 8)));
    assert_eq!(primitive_layout("unsigned long"), Some((8, 8)));
    assert_eq!(primitive_layout("long long"), Some((8, 8)));
    assert_eq!(primitive_layout("double"), Some((8, 8)));
    assert_eq!(primitive_layout("size_t"), Some((8, 8)));
    assert_eq!(primitive_layout("intptr_t"), Some((8, 8)));

    assert_eq!(primitive_layout("long double"), Some((16, 16)));
    assert_eq!(primitive_layout("__int128"), Some((16, 16)));
}

#[test]
fn test_basic_struct_layout_and_padding() {
    let code = r#"
    struct Simple {
        char a;
        int b;
        short c;
    };
    "#;

    let mut parser = AstParser::new().unwrap();
    let tree = parser.parse_content(code, Path::new("test.c")).unwrap();
    let mut resolver = StructLayoutResolver::new();
    let graph = resolver
        .resolve_struct_layouts(&tree, code, Path::new("test.c"))
        .unwrap();

    let layout = graph.get_struct("Simple").expect("Simple struct not found");
    assert_eq!(layout.total_size_bytes, 12);
    assert_eq!(layout.align_bytes, 4);

    assert_eq!(graph.get_field_offset("Simple", "a"), Some(0));
    assert_eq!(graph.get_field_offset("Simple", "b"), Some(4));
    assert_eq!(graph.get_field_offset("Simple", "c"), Some(8));
}

#[test]
fn test_nested_named_struct_layout() {
    let code = r#"
    struct Inner {
        char a;
        int b;
    };

    struct Outer {
        int x;
        struct Inner inner;
        char y;
    };
    "#;

    let mut parser = AstParser::new().unwrap();
    let tree = parser.parse_content(code, Path::new("test.c")).unwrap();
    let mut resolver = StructLayoutResolver::new();
    let graph = resolver
        .resolve_struct_layouts(&tree, code, Path::new("test.c"))
        .unwrap();

    let inner = graph.get_struct("Inner").expect("Inner not found");
    assert_eq!(inner.total_size_bytes, 8);
    assert_eq!(inner.align_bytes, 4);

    let outer = graph.get_struct("Outer").expect("Outer not found");
    assert_eq!(outer.total_size_bytes, 16);
    assert_eq!(outer.align_bytes, 4);

    assert_eq!(graph.get_field_offset("Outer", "x"), Some(0));
    assert_eq!(graph.get_field_offset("Outer", "inner"), Some(4));
    assert_eq!(graph.get_field_offset("Outer", "y"), Some(12));
}

#[test]
fn test_anonymous_nested_struct_and_union() {
    let code = r#"
    struct Container {
        int id;
        struct {
            char tag;
            double val;
        } data;
        char flag;
    };

    struct Variant {
        int type;
        union {
            int i;
            double d;
        } val;
    };
    "#;

    let mut parser = AstParser::new().unwrap();
    let tree = parser.parse_content(code, Path::new("test.c")).unwrap();
    let mut resolver = StructLayoutResolver::new();
    let graph = resolver
        .resolve_struct_layouts(&tree, code, Path::new("test.c"))
        .unwrap();

    let container = graph.get_struct("Container").expect("Container not found");
    assert_eq!(container.align_bytes, 8);
    // id: 0..4, padding 4..8, data: struct { tag: 0, val: 8 } -> size 16, align 8 at offset 8..24, flag: 24..25 -> total 32
    assert_eq!(graph.get_field_offset("Container", "id"), Some(0));
    assert_eq!(graph.get_field_offset("Container", "data"), Some(8));
    assert_eq!(graph.get_field_offset("Container", "flag"), Some(24));
    assert_eq!(container.total_size_bytes, 32);

    let variant = graph.get_struct("Variant").expect("Variant not found");
    assert_eq!(variant.align_bytes, 8);
    assert_eq!(graph.get_field_offset("Variant", "type"), Some(0));
    assert_eq!(graph.get_field_offset("Variant", "val"), Some(8));
    assert_eq!(variant.total_size_bytes, 16);
}

#[test]
fn test_union_layout() {
    let code = r#"
    union MultiData {
        char c;
        int i;
        double d;
        char buffer[10];
    };
    "#;

    let mut parser = AstParser::new().unwrap();
    let tree = parser.parse_content(code, Path::new("test.c")).unwrap();
    let mut resolver = StructLayoutResolver::new();
    let graph = resolver
        .resolve_struct_layouts(&tree, code, Path::new("test.c"))
        .unwrap();

    let union_layout = graph.get_union("MultiData").expect("MultiData not found");
    assert_eq!(union_layout.align_bytes, 8);
    // max size is 10 (buffer), padded to alignment 8 -> 16
    assert_eq!(union_layout.total_size_bytes, 16);

    assert_eq!(graph.get_field_offset("MultiData", "c"), Some(0));
    assert_eq!(graph.get_field_offset("MultiData", "i"), Some(0));
    assert_eq!(graph.get_field_offset("MultiData", "d"), Some(0));
    assert_eq!(graph.get_field_offset("MultiData", "buffer"), Some(0));
}

#[test]
fn test_self_referential_struct_pointers() {
    let code = r#"
    struct Node {
        int value;
        struct Node *next;
        struct Node *prev;
    };
    "#;

    let mut parser = AstParser::new().unwrap();
    let tree = parser.parse_content(code, Path::new("test.c")).unwrap();
    let mut resolver = StructLayoutResolver::new();
    let graph = resolver
        .resolve_struct_layouts(&tree, code, Path::new("test.c"))
        .unwrap();

    let node_layout = graph.get_struct("Node").expect("Node not found");
    assert_eq!(node_layout.align_bytes, 8);
    assert_eq!(graph.get_field_offset("Node", "value"), Some(0));
    assert_eq!(graph.get_field_offset("Node", "next"), Some(8));
    assert_eq!(graph.get_field_offset("Node", "prev"), Some(16));
    assert_eq!(node_layout.total_size_bytes, 24);
}

#[test]
fn test_function_pointer_table() {
    let code = r#"
    struct VTable {
        void (*init)(void *ctx);
        int (*process)(void *ctx, const char *data, int len);
        void (*cleanup)(void *ctx);
    };
    "#;

    let mut parser = AstParser::new().unwrap();
    let tree = parser.parse_content(code, Path::new("test.c")).unwrap();
    let mut resolver = StructLayoutResolver::new();
    let graph = resolver
        .resolve_struct_layouts(&tree, code, Path::new("test.c"))
        .unwrap();

    let vtable = graph.get_struct("VTable").expect("VTable not found");
    assert_eq!(vtable.align_bytes, 8);
    assert_eq!(vtable.total_size_bytes, 24);
    assert_eq!(graph.get_field_offset("VTable", "init"), Some(0));
    assert_eq!(graph.get_field_offset("VTable", "process"), Some(8));
    assert_eq!(graph.get_field_offset("VTable", "cleanup"), Some(16));

    // Verify fields are modeled as FunctionPointer
    match &vtable.fields[0].type_kind {
        TypeKind::FunctionPointer { parameters, .. } => {
            assert_eq!(parameters.len(), 1);
            assert!(parameters[0].is_pointer);
        }
        other => panic!("Expected FunctionPointer, got {:?}", other),
    }
}

#[test]
fn test_bitfield_layout() {
    let code = r#"
    struct BitFlags {
        unsigned int is_ready : 1;
        unsigned int is_active : 1;
        unsigned int mode : 4;
        unsigned int reserved : 2;
        int count;
    };
    "#;

    let mut parser = AstParser::new().unwrap();
    let tree = parser.parse_content(code, Path::new("test.c")).unwrap();
    let mut resolver = StructLayoutResolver::new();
    let graph = resolver
        .resolve_struct_layouts(&tree, code, Path::new("test.c"))
        .unwrap();



    let layout = graph.get_struct("BitFlags").expect("BitFlags not found");
    assert_eq!(layout.align_bytes, 4);
    assert_eq!(layout.total_size_bytes, 8);

    assert_eq!(graph.get_field_offset("BitFlags", "is_ready"), Some(0));
    assert_eq!(graph.get_field_offset("BitFlags", "is_active"), Some(0));
    assert_eq!(graph.get_field_offset("BitFlags", "mode"), Some(0));
    assert_eq!(graph.get_field_offset("BitFlags", "count"), Some(4));

    let f0 = &layout.fields[0];
    assert!(f0.is_bitfield);
    assert_eq!(f0.bit_width, Some(1));
    assert_eq!(f0.bit_offset, Some(0));

    let f1 = &layout.fields[1];
    assert!(f1.is_bitfield);
    assert_eq!(f1.bit_width, Some(1));
    assert_eq!(f1.bit_offset, Some(1));

    let f2 = &layout.fields[2];
    assert!(f2.is_bitfield);
    assert_eq!(f2.bit_width, Some(4));
    assert_eq!(f2.bit_offset, Some(2));
}

#[test]
fn test_typedef_alias_chains() {
    let code = r#"
    typedef struct Point {
        int x;
        int y;
    } Point_t;

    typedef Point_t ScreenPoint;
    "#;

    let mut parser = AstParser::new().unwrap();
    let tree = parser.parse_content(code, Path::new("test.c")).unwrap();
    let mut resolver = StructLayoutResolver::new();
    let graph = resolver
        .resolve_struct_layouts(&tree, code, Path::new("test.c"))
        .unwrap();

    // Queryable by struct tag, typedef name, and alias
    assert_eq!(graph.get_field_offset("Point", "x"), Some(0));
    assert_eq!(graph.get_field_offset("Point_t", "y"), Some(4));
    assert_eq!(graph.get_field_offset("struct Point", "x"), Some(0));
}

#[test]
fn test_scan_directory_ast_e2e() {
    let temp_dir = tempfile::tempdir().unwrap();
    let h_path = temp_dir.path().join("target.h");
    let c_path = temp_dir.path().join("target.c");

    let header_code = r#"
    #ifndef TARGET_H
    #define TARGET_H

    #include <stddef.h>

    typedef struct TargetCtx {
        int id;
        char *buffer;
        size_t size;
    } TargetCtx;

    TargetCtx *target_init(size_t initial_size);
    int target_process(TargetCtx *ctx, const char *input, size_t len);
    void target_cleanup(TargetCtx *ctx);

    #endif
    "#;

    let source_code = r#"
    #include "target.h"
    #include <stdlib.h>
    #include <string.h>

    static void internal_helper(TargetCtx *ctx) {
        if (ctx) {
            ctx->id = 0;
        }
    }

    TargetCtx *target_init(size_t initial_size) {
        TargetCtx *ctx = (TargetCtx *)malloc(sizeof(TargetCtx));
        if (!ctx) return NULL;
        ctx->id = 1;
        ctx->buffer = (char *)malloc(initial_size);
        ctx->size = initial_size;
        return ctx;
    }

    int target_process(TargetCtx *ctx, const char *input, size_t len) {
        if (!ctx || !ctx->buffer) return -1;
        if (len > ctx->size) len = ctx->size;
        memcpy(ctx->buffer, input, len);
        return 0;
    }

    void target_cleanup(TargetCtx *ctx) {
        if (ctx) {
            if (ctx->buffer) free(ctx->buffer);
            free(ctx);
        }
    }
    "#;

    std::fs::write(&h_path, header_code).unwrap();
    std::fs::write(&c_path, source_code).unwrap();

    let profile = scan_directory_ast(temp_dir.path()).unwrap();

    // 1. Check public headers
    assert_eq!(profile.public_headers.len(), 1);
    assert_eq!(profile.public_headers[0], h_path);

    // 2. Check functions extracted
    assert!(!profile.functions.is_empty());
    let init_func = profile
        .functions
        .iter()
        .find(|f| f.name == "target_init")
        .expect("target_init not found");
    assert!(init_func.is_exported);
    assert!(!init_func.is_static);

    let helper_func = profile
        .functions
        .iter()
        .find(|f| f.name == "internal_helper")
        .expect("internal_helper not found");
    assert!(helper_func.is_static);
    assert!(!helper_func.is_exported);

    // 3. Check structs populated
    assert!(!profile.structs.is_empty());
    let ctx_struct = profile
        .structs
        .iter()
        .find(|s| s.name == "TargetCtx")
        .expect("TargetCtx struct not found");
    assert_eq!(ctx_struct.fields.len(), 3);
    assert_eq!(ctx_struct.fields[0].name, "id");
    assert_eq!(ctx_struct.fields[0].offset_bytes, 0);
    assert_eq!(ctx_struct.fields[1].name, "buffer");
    assert_eq!(ctx_struct.fields[1].offset_bytes, 8);
    assert_eq!(ctx_struct.fields[2].name, "size");
    assert_eq!(ctx_struct.fields[2].offset_bytes, 16);
    assert_eq!(ctx_struct.total_size_bytes, 24);

    // 4. Check dangerous sinks detected
    assert!(!profile.dangerous_sinks.is_empty());
    let memcpy_sink = profile
        .dangerous_sinks
        .iter()
        .find(|s| s.sink_type == "memcpy")
        .expect("memcpy dangerous sink not found");
    assert_eq!(memcpy_sink.function_name, "target_process");

    let malloc_sink = profile
        .dangerous_sinks
        .iter()
        .find(|s| s.sink_type == "malloc")
        .expect("malloc dangerous sink not found");
    assert_eq!(malloc_sink.function_name, "target_init");

    // 5. Check layout graph
    assert!(profile.layout_graph.is_some());
    let lg = profile.layout_graph.unwrap();
    assert_eq!(lg.get_field_offset("TargetCtx", "buffer"), Some(8));
}
