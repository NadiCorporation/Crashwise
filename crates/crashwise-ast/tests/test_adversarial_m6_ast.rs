use crashwise_ast::{AstParser, StructLayoutResolver};
use std::path::Path;
use std::process::Command;

/// Helper: Ask GCC to compile a C file that prints canonical offsets and sizes
fn get_gcc_oracle_output(c_code: &str) -> Option<String> {
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
fn test_m6_multidimensional_arrays_and_array_of_structs() {
    let code = r#"
    struct Element {
        char c;
        double d;
    };

    struct ArrayMatrix {
        short header;
        struct Element matrix[2][3];
        int footer;
    };

    struct PrimitiveMultiDim {
        char tag;
        int tensor[2][3][4];
        long sentinel;
    };
    "#;

    let mut parser = AstParser::new().unwrap();
    let tree = parser.parse_content(code, Path::new("test.c")).unwrap();
    let mut resolver = StructLayoutResolver::new();
    let graph = resolver
        .resolve_struct_layouts(&tree, code, Path::new("test.c"))
        .unwrap();

    let elem = graph.get_struct("Element").expect("Element not found");
    assert_eq!(elem.total_size_bytes, 16);
    assert_eq!(elem.align_bytes, 8);
    assert_eq!(graph.get_field_offset("Element", "c"), Some(0));
    assert_eq!(graph.get_field_offset("Element", "d"), Some(8));

    let matrix = graph.get_struct("ArrayMatrix").expect("ArrayMatrix not found");
    // header: offset 0, size 2. Padding to align 8: 6 bytes.
    // matrix: offset 8, size 2 * 3 * 16 = 96 bytes.
    // footer: offset 8 + 96 = 104, size 4 bytes.
    // struct tail padding to multiple of 8: 4 bytes -> total 112 bytes, align 8.
    assert_eq!(matrix.total_size_bytes, 112);
    assert_eq!(matrix.align_bytes, 8);
    assert_eq!(graph.get_field_offset("ArrayMatrix", "header"), Some(0));
    assert_eq!(graph.get_field_offset("ArrayMatrix", "matrix"), Some(8));
    assert_eq!(graph.get_field_offset("ArrayMatrix", "footer"), Some(104));

    let tensor_struct = graph.get_struct("PrimitiveMultiDim").expect("PrimitiveMultiDim not found");
    // tag: offset 0, size 1. Padding to align 4: 3 bytes.
    // tensor: 2 * 3 * 4 * 4 = 96 bytes. offset 4.
    // sentinel: offset 4 + 96 = 100. Padding to align 8: 4 bytes -> offset 104.
    // sentinel size 8 -> total 112 bytes, align 8.
    assert_eq!(tensor_struct.total_size_bytes, 112);
    assert_eq!(tensor_struct.align_bytes, 8);
    assert_eq!(graph.get_field_offset("PrimitiveMultiDim", "tag"), Some(0));
    assert_eq!(graph.get_field_offset("PrimitiveMultiDim", "tensor"), Some(4));
    assert_eq!(graph.get_field_offset("PrimitiveMultiDim", "sentinel"), Some(104));

    // Verify against GCC Oracle
    let oracle_c = r#"
    #include <stdio.h>
    #include <stddef.h>

    struct Element { char c; double d; };
    struct ArrayMatrix { short header; struct Element matrix[2][3]; int footer; };
    struct PrimitiveMultiDim { char tag; int tensor[2][3][4]; long sentinel; };

    int main() {
        printf("ArrayMatrix: size=%zu align=%zu h=%zu m=%zu f=%zu\n",
            sizeof(struct ArrayMatrix), _Alignof(struct ArrayMatrix),
            offsetof(struct ArrayMatrix, header),
            offsetof(struct ArrayMatrix, matrix),
            offsetof(struct ArrayMatrix, footer));
        printf("PrimitiveMultiDim: size=%zu align=%zu t=%zu ten=%zu s=%zu\n",
            sizeof(struct PrimitiveMultiDim), _Alignof(struct PrimitiveMultiDim),
            offsetof(struct PrimitiveMultiDim, tag),
            offsetof(struct PrimitiveMultiDim, tensor),
            offsetof(struct PrimitiveMultiDim, sentinel));
        return 0;
    }
    "#;

    let oracle_out = get_gcc_oracle_output(oracle_c).expect("GCC oracle failed");
    let lines: Vec<&str> = oracle_out.trim().lines().collect();
    assert_eq!(lines[0], "ArrayMatrix: size=112 align=8 h=0 m=8 f=104");
    assert_eq!(lines[1], "PrimitiveMultiDim: size=112 align=8 t=0 ten=4 s=104");
}

#[test]
fn test_m6_zero_width_bitfield_boundary_rules() {
    let code = r#"
    struct BitfieldChaos {
        unsigned char a : 3;
        unsigned char b : 4;
        unsigned int : 0;
        unsigned short c : 5;
        unsigned short d : 11;
        unsigned long : 0;
        unsigned long e : 1;
    };
    "#;

    let mut parser = AstParser::new().unwrap();
    let tree = parser.parse_content(code, Path::new("test.c")).unwrap();
    let mut resolver = StructLayoutResolver::new();
    let graph = resolver
        .resolve_struct_layouts(&tree, code, Path::new("test.c"))
        .unwrap();

    let s = graph.get_struct("BitfieldChaos").expect("BitfieldChaos not found");
    assert_eq!(s.align_bytes, 8);
    assert_eq!(s.total_size_bytes, 16);

    assert_eq!(graph.get_field_offset("BitfieldChaos", "a"), Some(0));
    assert_eq!(graph.get_field_offset("BitfieldChaos", "b"), Some(0));
    assert_eq!(graph.get_field_offset("BitfieldChaos", "c"), Some(4));
    assert_eq!(graph.get_field_offset("BitfieldChaos", "d"), Some(4));
    assert_eq!(graph.get_field_offset("BitfieldChaos", "e"), Some(8));

    // Verify against GCC Oracle
    let oracle_c = r#"
    #include <stdio.h>
    #include <stddef.h>

    struct BitfieldChaos {
        unsigned char a : 3;
        unsigned char b : 4;
        unsigned int : 0;
        unsigned short c : 5;
        unsigned short d : 11;
        unsigned long : 0;
        unsigned long e : 1;
    };

    int main() {
        printf("BitfieldChaos: size=%zu align=%zu\n",
            sizeof(struct BitfieldChaos), _Alignof(struct BitfieldChaos));
        return 0;
    }
    "#;

    let oracle_out = get_gcc_oracle_output(oracle_c).expect("GCC oracle failed");
    assert_eq!(oracle_out.trim(), "BitfieldChaos: size=16 align=8");
}

#[test]
fn test_m6_pragma_pack_push_pop_scoping() {
    let code = r#"
    struct UnpackedBefore {
        char c;
        int i;
        double d;
    };

    #pragma pack(push, 1)

    struct PackedInner {
        char c;
        int i;
        double d;
    };

    #pragma pack(pop)

    struct UnpackedAfter {
        char c;
        int i;
        double d;
    };
    "#;

    let mut parser = AstParser::new().unwrap();
    let tree = parser.parse_content(code, Path::new("test.c")).unwrap();
    let mut resolver = StructLayoutResolver::new();
    let graph = resolver
        .resolve_struct_layouts(&tree, code, Path::new("test.c"))
        .unwrap();

    let before = graph.get_struct("UnpackedBefore").expect("UnpackedBefore");
    assert_eq!(before.align_bytes, 8);
    assert_eq!(before.total_size_bytes, 16);
    assert!(!before.is_packed);
    assert_eq!(graph.get_field_offset("UnpackedBefore", "c"), Some(0));
    assert_eq!(graph.get_field_offset("UnpackedBefore", "i"), Some(4));
    assert_eq!(graph.get_field_offset("UnpackedBefore", "d"), Some(8));

    let packed = graph.get_struct("PackedInner").expect("PackedInner");
    assert_eq!(packed.align_bytes, 1);
    assert_eq!(packed.total_size_bytes, 13); // 1 + 4 + 8 = 13
    assert!(packed.is_packed);
    assert_eq!(graph.get_field_offset("PackedInner", "c"), Some(0));
    assert_eq!(graph.get_field_offset("PackedInner", "i"), Some(1));
    assert_eq!(graph.get_field_offset("PackedInner", "d"), Some(5));

    let after = graph.get_struct("UnpackedAfter").expect("UnpackedAfter");
    assert_eq!(after.align_bytes, 8);
    assert_eq!(after.total_size_bytes, 16);
    assert!(!after.is_packed);
    assert_eq!(graph.get_field_offset("UnpackedAfter", "c"), Some(0));
    assert_eq!(graph.get_field_offset("UnpackedAfter", "i"), Some(4));
    assert_eq!(graph.get_field_offset("UnpackedAfter", "d"), Some(8));

    // Verify against GCC Oracle
    let oracle_c = r#"
    #include <stdio.h>
    #include <stddef.h>

    struct UnpackedBefore { char c; int i; double d; };
    #pragma pack(push, 1)
    struct PackedInner { char c; int i; double d; };
    #pragma pack(pop)
    struct UnpackedAfter { char c; int i; double d; };

    int main() {
        printf("Before: size=%zu align=%zu c=%zu i=%zu d=%zu\n",
            sizeof(struct UnpackedBefore), _Alignof(struct UnpackedBefore),
            offsetof(struct UnpackedBefore, c), offsetof(struct UnpackedBefore, i), offsetof(struct UnpackedBefore, d));
        printf("Packed: size=%zu align=%zu c=%zu i=%zu d=%zu\n",
            sizeof(struct PackedInner), _Alignof(struct PackedInner),
            offsetof(struct PackedInner, c), offsetof(struct PackedInner, i), offsetof(struct PackedInner, d));
        printf("After: size=%zu align=%zu c=%zu i=%zu d=%zu\n",
            sizeof(struct UnpackedAfter), _Alignof(struct UnpackedAfter),
            offsetof(struct UnpackedAfter, c), offsetof(struct UnpackedAfter, i), offsetof(struct UnpackedAfter, d));
        return 0;
    }
    "#;

    let oracle_out = get_gcc_oracle_output(oracle_c).expect("GCC oracle failed");
    let lines: Vec<&str> = oracle_out.trim().lines().collect();
    assert_eq!(lines[0], "Before: size=16 align=8 c=0 i=4 d=8");
    assert_eq!(lines[1], "Packed: size=13 align=1 c=0 i=1 d=5");
    assert_eq!(lines[2], "After: size=16 align=8 c=0 i=4 d=8");
}

#[test]
fn test_m6_deeply_nested_alternating_structs_and_unions() {
    let code = r#"
    struct Level6 {
        char byte;
        union {
            int i;
            struct {
                short s;
                union {
                    float f;
                    struct {
                        double d;
                        char flag;
                    } deepest;
                } u2;
            } s2;
        } u1;
        long guard;
    };
    "#;

    let mut parser = AstParser::new().unwrap();
    let tree = parser.parse_content(code, Path::new("test.c")).unwrap();
    let mut resolver = StructLayoutResolver::new();
    let graph = resolver
        .resolve_struct_layouts(&tree, code, Path::new("test.c"))
        .unwrap();

    let l6 = graph.get_struct("Level6").expect("Level6 not found");
    assert_eq!(l6.align_bytes, 8);
    assert_eq!(graph.get_field_offset("Level6", "byte"), Some(0));
    assert_eq!(graph.get_field_offset("Level6", "u1"), Some(8));

    // Verify against GCC Oracle
    let oracle_c = r#"
    #include <stdio.h>
    #include <stddef.h>

    struct Level6 {
        char byte;
        union {
            int i;
            struct {
                short s;
                union {
                    float f;
                    struct {
                        double d;
                        char flag;
                    } deepest;
                } u2;
            } s2;
        } u1;
        long guard;
    };

    int main() {
        printf("Level6: size=%zu align=%zu byte=%zu u1=%zu guard=%zu deepest_d=%zu\n",
            sizeof(struct Level6), _Alignof(struct Level6),
            offsetof(struct Level6, byte),
            offsetof(struct Level6, u1),
            offsetof(struct Level6, guard),
            offsetof(struct Level6, u1.s2.u2.deepest.d));
        return 0;
    }
    "#;

    let oracle_out = get_gcc_oracle_output(oracle_c).expect("GCC oracle failed");
    let parts: Vec<&str> = oracle_out.split_whitespace().collect();
    let gcc_size: usize = parts[1].split('=').nth(1).unwrap().parse().unwrap();
    let gcc_align: usize = parts[2].split('=').nth(1).unwrap().parse().unwrap();
    let gcc_guard_offset: usize = parts[5].split('=').nth(1).unwrap().parse().unwrap();

    assert_eq!(l6.total_size_bytes, gcc_size);
    assert_eq!(l6.align_bytes, gcc_align);
    assert_eq!(graph.get_field_offset("Level6", "guard"), Some(gcc_guard_offset));
}

#[test]
fn test_m6_mutually_recursive_pointers_and_multiple_declarators() {
    let code = r#"
    struct NodeB;

    struct NodeA {
        int id;
        struct NodeB *neighbor;
        struct NodeA *parent, *left, *right;
    };

    struct NodeB {
        char tag;
        struct NodeA *owner;
        int flags, weight, priority;
    };
    "#;

    let mut parser = AstParser::new().unwrap();
    let tree = parser.parse_content(code, Path::new("test.c")).unwrap();
    let mut resolver = StructLayoutResolver::new();
    let graph = resolver
        .resolve_struct_layouts(&tree, code, Path::new("test.c"))
        .unwrap();

    let a = graph.get_struct("NodeA").expect("NodeA not found");
    assert_eq!(a.total_size_bytes, 40);
    assert_eq!(a.align_bytes, 8);
    assert_eq!(graph.get_field_offset("NodeA", "id"), Some(0));
    assert_eq!(graph.get_field_offset("NodeA", "neighbor"), Some(8));
    assert_eq!(graph.get_field_offset("NodeA", "parent"), Some(16));
    assert_eq!(graph.get_field_offset("NodeA", "left"), Some(24));
    assert_eq!(graph.get_field_offset("NodeA", "right"), Some(32));

    let b = graph.get_struct("NodeB").expect("NodeB not found");
    assert_eq!(b.total_size_bytes, 32);
    assert_eq!(b.align_bytes, 8);
    assert_eq!(graph.get_field_offset("NodeB", "tag"), Some(0));
    assert_eq!(graph.get_field_offset("NodeB", "owner"), Some(8));
    assert_eq!(graph.get_field_offset("NodeB", "flags"), Some(16));
    assert_eq!(graph.get_field_offset("NodeB", "weight"), Some(20));
    assert_eq!(graph.get_field_offset("NodeB", "priority"), Some(24));

    // Verify against GCC Oracle
    let oracle_c = r#"
    #include <stdio.h>
    #include <stddef.h>

    struct NodeB;
    struct NodeA {
        int id;
        struct NodeB *neighbor;
        struct NodeA *parent, *left, *right;
    };
    struct NodeB {
        char tag;
        struct NodeA *owner;
        int flags, weight, priority;
    };

    int main() {
        printf("NodeA: size=%zu align=%zu id=%zu n=%zu p=%zu l=%zu r=%zu\n",
            sizeof(struct NodeA), _Alignof(struct NodeA),
            offsetof(struct NodeA, id), offsetof(struct NodeA, neighbor),
            offsetof(struct NodeA, parent), offsetof(struct NodeA, left), offsetof(struct NodeA, right));
        printf("NodeB: size=%zu align=%zu tag=%zu owner=%zu f=%zu w=%zu pri=%zu\n",
            sizeof(struct NodeB), _Alignof(struct NodeB),
            offsetof(struct NodeB, tag), offsetof(struct NodeB, owner),
            offsetof(struct NodeB, flags), offsetof(struct NodeB, weight), offsetof(struct NodeB, priority));
        return 0;
    }
    "#;

    let oracle_out = get_gcc_oracle_output(oracle_c).expect("GCC oracle failed");
    let lines: Vec<&str> = oracle_out.trim().lines().collect();
    assert_eq!(lines[0], "NodeA: size=40 align=8 id=0 n=8 p=16 l=24 r=32");
    assert_eq!(lines[1], "NodeB: size=32 align=8 tag=0 owner=8 f=16 w=20 pri=24");
}
