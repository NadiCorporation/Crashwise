use crashwise_ast::{AstParser, StructLayoutResolver};
use std::path::Path;
use std::process::Command;

/// Helper: Ask GCC to compile a C file that prints canonical offsets and sizes
fn get_c_compiler_layout(c_code: &str) -> Option<String> {
    let temp_dir = tempfile::tempdir().ok()?;
    let c_file = temp_dir.path().join("oracle.c");
    let bin_file = temp_dir.path().join("oracle");

    std::fs::write(&c_file, c_code).ok()?;

    let compile_status = Command::new("gcc")
        .arg("-O0")
        .arg(&c_file)
        .arg("-o")
        .arg(&bin_file)
        .status()
        .ok()?;

    if !compile_status.success() {
        return None;
    }

    let output = Command::new(&bin_file).output().ok()?;
    if !output.status.success() {
        return None;
    }

    String::from_utf8(output.stdout).ok()
}

#[test]
fn challenge_deeply_nested_named_structs() {
    let code = r#"
    struct L1 {
        char a;
        int b;
    };

    struct L2 {
        short s;
        struct L1 l1;
        double d;
    };

    struct L3 {
        char c;
        struct L2 l2;
        float f;
    };

    struct L4 {
        int x;
        struct L3 l3;
        long y;
    };
    "#;

    let mut parser = AstParser::new().unwrap();
    let tree = parser.parse_content(code, Path::new("test.c")).unwrap();
    let mut resolver = StructLayoutResolver::new();
    let graph = resolver
        .resolve_struct_layouts(&tree, code, Path::new("test.c"))
        .unwrap();

    let l1 = graph.get_struct("L1").expect("L1 not found");
    assert_eq!(l1.total_size_bytes, 8);
    assert_eq!(l1.align_bytes, 4);
    assert_eq!(graph.get_field_offset("L1", "a"), Some(0));
    assert_eq!(graph.get_field_offset("L1", "b"), Some(4));

    let l2 = graph.get_struct("L2").expect("L2 not found");
    assert_eq!(l2.total_size_bytes, 24);
    assert_eq!(l2.align_bytes, 8);
    assert_eq!(graph.get_field_offset("L2", "s"), Some(0));
    assert_eq!(graph.get_field_offset("L2", "l1"), Some(4));
    assert_eq!(graph.get_field_offset("L2", "d"), Some(16));

    let l3 = graph.get_struct("L3").expect("L3 not found");
    assert_eq!(l3.total_size_bytes, 40);
    assert_eq!(l3.align_bytes, 8);
    assert_eq!(graph.get_field_offset("L3", "c"), Some(0));
    assert_eq!(graph.get_field_offset("L3", "l2"), Some(8));
    assert_eq!(graph.get_field_offset("L3", "f"), Some(32));

    let l4 = graph.get_struct("L4").expect("L4 not found");
    assert_eq!(l4.total_size_bytes, 56);
    assert_eq!(l4.align_bytes, 8);
    assert_eq!(graph.get_field_offset("L4", "x"), Some(0));
    assert_eq!(graph.get_field_offset("L4", "l3"), Some(8));
    assert_eq!(graph.get_field_offset("L4", "y"), Some(48));

    // Verify against GCC oracle
    let oracle_c = r#"
    #include <stdio.h>
    #include <stddef.h>

    struct L1 { char a; int b; };
    struct L2 { short s; struct L1 l1; double d; };
    struct L3 { char c; struct L2 l2; float f; };
    struct L4 { int x; struct L3 l3; long y; };

    int main() {
        printf("L4: size=%zu align=%zu x=%zu l3=%zu y=%zu\n",
            sizeof(struct L4), _Alignof(struct L4),
            offsetof(struct L4, x), offsetof(struct L4, l3), offsetof(struct L4, y));
        return 0;
    }
    "#;

    let oracle_out = get_c_compiler_layout(oracle_c).expect("GCC oracle failed");
    assert_eq!(oracle_out.trim(), "L4: size=56 align=8 x=0 l3=8 y=48");
}

#[test]
fn challenge_deeply_nested_anonymous_structs() {
    let code = r#"
    struct DeepAnonTree {
        int id;
        struct {
            char tag;
            union {
                int ival;
                double dval;
            } u;
            struct {
                short flags;
                char *name;
            } inner;
        } payload;
    };
    "#;

    let mut parser = AstParser::new().unwrap();
    let tree = parser.parse_content(code, Path::new("test.c")).unwrap();
    let mut resolver = StructLayoutResolver::new();
    let graph = resolver
        .resolve_struct_layouts(&tree, code, Path::new("test.c"))
        .unwrap();

    let root = graph.get_struct("DeepAnonTree").expect("DeepAnonTree not found");
    assert_eq!(root.align_bytes, 8);
    assert_eq!(graph.get_field_offset("DeepAnonTree", "id"), Some(0));
    assert_eq!(graph.get_field_offset("DeepAnonTree", "payload"), Some(8));

    let oracle_c = r#"
    #include <stdio.h>
    #include <stddef.h>

    struct DeepAnonTree {
        int id;
        struct {
            char tag;
            union {
                int ival;
                double dval;
            } u;
            struct {
                short flags;
                char *name;
            } inner;
        } payload;
    };

    int main() {
        printf("DeepAnon: size=%zu align=%zu id=%zu payload=%zu\n",
            sizeof(struct DeepAnonTree), _Alignof(struct DeepAnonTree),
            offsetof(struct DeepAnonTree, id), offsetof(struct DeepAnonTree, payload));
        return 0;
    }
    "#;
    let oracle_out = get_c_compiler_layout(oracle_c).expect("GCC oracle failed");
    println!("Oracle output: {}", oracle_out);
    let expected_size: usize = oracle_out.split("size=").nth(1).unwrap().split_whitespace().next().unwrap().parse().unwrap();
    assert_eq!(root.total_size_bytes, expected_size, "Mismatch in DeepAnonTree total size");
}

#[test]
fn challenge_cyclic_graph_structs() {
    let code = r#"
    struct GraphNode;

    struct GraphEdge {
        int weight;
        struct GraphNode *src;
        struct GraphNode *dst;
        struct GraphEdge *next;
    };

    struct GraphNode {
        int id;
        struct GraphEdge *first_edge;
        struct GraphNode *parent;
        struct GraphNode *left_child;
        struct GraphNode *right_sibling;
    };
    "#;

    let mut parser = AstParser::new().unwrap();
    let tree = parser.parse_content(code, Path::new("test.c")).unwrap();
    let mut resolver = StructLayoutResolver::new();
    let graph = resolver
        .resolve_struct_layouts(&tree, code, Path::new("test.c"))
        .unwrap();

    let edge = graph.get_struct("GraphEdge").expect("GraphEdge not found");
    assert_eq!(edge.align_bytes, 8);
    assert_eq!(edge.total_size_bytes, 32);
    assert_eq!(graph.get_field_offset("GraphEdge", "weight"), Some(0));
    assert_eq!(graph.get_field_offset("GraphEdge", "src"), Some(8));
    assert_eq!(graph.get_field_offset("GraphEdge", "dst"), Some(16));
    assert_eq!(graph.get_field_offset("GraphEdge", "next"), Some(24));

    let node = graph.get_struct("GraphNode").expect("GraphNode not found");
    assert_eq!(node.align_bytes, 8);
    assert_eq!(node.total_size_bytes, 40);
    assert_eq!(graph.get_field_offset("GraphNode", "id"), Some(0));
    assert_eq!(graph.get_field_offset("GraphNode", "first_edge"), Some(8));
    assert_eq!(graph.get_field_offset("GraphNode", "parent"), Some(16));
    assert_eq!(graph.get_field_offset("GraphNode", "left_child"), Some(24));
    assert_eq!(graph.get_field_offset("GraphNode", "right_sibling"), Some(32));
}

#[test]
fn challenge_bitfields_with_zero_width_markers() {
    let code = r#"
    struct ZeroWidthBF {
        int a : 3;
        int : 0;
        int b : 5;
    };
    "#;

    let mut parser = AstParser::new().unwrap();
    let tree = parser.parse_content(code, Path::new("test.c")).unwrap();
    let mut resolver = StructLayoutResolver::new();
    let graph = resolver
        .resolve_struct_layouts(&tree, code, Path::new("test.c"))
        .unwrap();

    let layout = graph.get_struct("ZeroWidthBF").expect("ZeroWidthBF not found");

    let oracle_c = r#"
    #include <stdio.h>
    #include <stddef.h>

    struct ZeroWidthBF {
        int a : 3;
        int : 0;
        int b : 5;
    };

    int main() {
        printf("ZeroWidthBF: size=%zu align=%zu\n",
            sizeof(struct ZeroWidthBF), _Alignof(struct ZeroWidthBF));
        return 0;
    }
    "#;
    let oracle_out = get_c_compiler_layout(oracle_c).expect("GCC oracle failed");
    println!("Oracle output: {}", oracle_out);

    // Canonical C on AMD64: sizeof is 8 because int : 0 closes the first 4-byte unit!
    let expected_size: usize = oracle_out.split("size=").nth(1).unwrap().split_whitespace().next().unwrap().parse().unwrap();
    assert_eq!(expected_size, 8);

    println!("Crashwise resolved size: {}, align: {}", layout.total_size_bytes, layout.align_bytes);
    for (i, f) in layout.fields.iter().enumerate() {
        println!("Field {}: name='{}' offset={} size={} is_bf={} bit_w={:?} bit_off={:?}",
            i, f.name, f.offset_bytes, f.size_bytes, f.is_bitfield, f.bit_width, f.bit_offset);
    }

    assert_eq!(layout.total_size_bytes, 8, "Zero-width bitfield should force next bitfield into next storage unit, total size should be 8");
    assert_eq!(graph.get_field_offset("ZeroWidthBF", "b"), Some(4), "Field 'b' should be at offset 4 due to zero-width bitfield");
}

#[test]
fn challenge_packed_struct_pragma() {
    let code = r#"
    #pragma pack(1)
    struct PragmaPacked {
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

    let layout = graph.get_struct("PragmaPacked").expect("PragmaPacked not found");
    println!("PragmaPacked: is_packed={} size={} align={}", layout.is_packed, layout.total_size_bytes, layout.align_bytes);

    let oracle_c = r#"
    #include <stdio.h>
    #include <stddef.h>

    #pragma pack(1)
    struct PragmaPacked {
        char a;
        int b;
        short c;
    };

    int main() {
        printf("PragmaPacked: size=%zu align=%zu a=%zu b=%zu c=%zu\n",
            sizeof(struct PragmaPacked), _Alignof(struct PragmaPacked),
            offsetof(struct PragmaPacked, a), offsetof(struct PragmaPacked, b), offsetof(struct PragmaPacked, c));
        return 0;
    }
    "#;
    let oracle_out = get_c_compiler_layout(oracle_c).expect("GCC oracle failed");
    println!("Oracle output: {}", oracle_out);

    assert!(layout.is_packed, "Struct defined under #pragma pack(1) must be flagged as is_packed = true");
    assert_eq!(layout.total_size_bytes, 7, "Pragma packed struct size should be 7");
    assert_eq!(layout.align_bytes, 1, "Pragma packed struct alignment should be 1");
    assert_eq!(graph.get_field_offset("PragmaPacked", "b"), Some(1));
    assert_eq!(graph.get_field_offset("PragmaPacked", "c"), Some(5));
}

#[test]
fn challenge_union_with_nested_struct() {
    let code = r#"
    union UnionWithStruct {
        struct {
            char buf[32];
            int count;
        } s;
        char raw[8];
    };
    "#;

    let mut parser = AstParser::new().unwrap();
    let tree = parser.parse_content(code, Path::new("test.c")).unwrap();
    let mut resolver = StructLayoutResolver::new();
    let graph = resolver
        .resolve_struct_layouts(&tree, code, Path::new("test.c"))
        .unwrap();

    let u = graph.get_union("UnionWithStruct").expect("UnionWithStruct not found");
    println!("UnionWithStruct: size={} align={}", u.total_size_bytes, u.align_bytes);
    for v in &u.variants {
        println!("Variant: {} size={} align={}", v.name, v.size_bytes, v.align_bytes);
    }

    let oracle_c = r#"
    #include <stdio.h>
    #include <stddef.h>

    union UnionWithStruct {
        struct {
            char buf[32];
            int count;
        } s;
        char raw[8];
    };

    int main() {
        printf("UnionWithStruct: size=%zu align=%zu\n",
            sizeof(union UnionWithStruct), _Alignof(union UnionWithStruct));
        return 0;
    }
    "#;
    let oracle_out = get_c_compiler_layout(oracle_c).expect("GCC oracle failed");
    println!("Oracle output: {}", oracle_out);
    // In canonical C: inner struct has 32 chars + 4 int = 36 bytes.
    // Union size must be 36 (or aligned to 4 -> 36).
    assert_eq!(u.total_size_bytes, 36, "Union containing nested struct must calculate variant size from nested struct (36 bytes), not fallback to 8 bytes");
}
