use crashwise_ast::{AstParser, StructLayoutResolver, TypeKind};
use crashwise_core::db::Database;
use std::path::Path;
use std::process::Command;
use std::sync::{Arc, Barrier};
use std::thread;

/// Helper: Invokes canonical GCC on AMD64 Linux to obtain exact sizeof, _Alignof, and offsetof
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

// =========================================================================
// 1. AMD64 Layout: Deeply nested structs and unions (3+ levels)
// =========================================================================
#[test]
fn challenge_deeply_nested_structs_and_unions_3plus_levels() {
    let code = r#"
    struct InnerCore {
        char tag;
        int id;
        short flag;
    };

    union MidVariant {
        struct InnerCore core;
        double weight;
        char bytes[16];
    };

    struct ContainerNode {
        short header;
        union MidVariant variant;
        long timestamp;
    };

    struct OuterRoot {
        int prefix;
        struct ContainerNode node;
        void *ptr;
    };
    "#;

    let oracle_c = r#"
    #include <stdio.h>
    #include <stddef.h>

    struct InnerCore { char tag; int id; short flag; };
    union MidVariant { struct InnerCore core; double weight; char bytes[16]; };
    struct ContainerNode { short header; union MidVariant variant; long timestamp; };
    struct OuterRoot { int prefix; struct ContainerNode node; void *ptr; };

    int main() {
        printf("InnerCore: size=%zu align=%zu id_off=%zu flag_off=%zu\n",
            sizeof(struct InnerCore), _Alignof(struct InnerCore),
            offsetof(struct InnerCore, id), offsetof(struct InnerCore, flag));
        printf("ContainerNode: size=%zu align=%zu var_off=%zu ts_off=%zu\n",
            sizeof(struct ContainerNode), _Alignof(struct ContainerNode),
            offsetof(struct ContainerNode, variant), offsetof(struct ContainerNode, timestamp));
        printf("OuterRoot: size=%zu align=%zu node_off=%zu ptr_off=%zu\n",
            sizeof(struct OuterRoot), _Alignof(struct OuterRoot),
            offsetof(struct OuterRoot, node), offsetof(struct OuterRoot, ptr));
        return 0;
    }
    "#;

    let oracle_out = get_c_compiler_layout(oracle_c).expect("GCC oracle execution failed");
    println!("Oracle Output:\n{}", oracle_out);

    let mut parser = AstParser::new().unwrap();
    let tree = parser.parse_content(code, Path::new("nested.c")).unwrap();
    let mut resolver = StructLayoutResolver::new();
    let graph = resolver
        .resolve_struct_layouts(&tree, code, Path::new("nested.c"))
        .unwrap();

    let inner = graph.get_struct("InnerCore").expect("InnerCore not found");
    assert_eq!(inner.total_size_bytes, 12);
    assert_eq!(inner.align_bytes, 4);
    assert_eq!(graph.get_field_offset("InnerCore", "tag"), Some(0));
    assert_eq!(graph.get_field_offset("InnerCore", "id"), Some(4));
    assert_eq!(graph.get_field_offset("InnerCore", "flag"), Some(8));

    let container = graph.get_struct("ContainerNode").expect("ContainerNode not found");
    assert_eq!(container.total_size_bytes, 32);
    assert_eq!(container.align_bytes, 8);
    assert_eq!(graph.get_field_offset("ContainerNode", "header"), Some(0));
    assert_eq!(graph.get_field_offset("ContainerNode", "variant"), Some(8));
    assert_eq!(graph.get_field_offset("ContainerNode", "timestamp"), Some(24));

    let outer = graph.get_struct("OuterRoot").expect("OuterRoot not found");
    assert_eq!(outer.total_size_bytes, 48);
    assert_eq!(outer.align_bytes, 8);
    assert_eq!(graph.get_field_offset("OuterRoot", "prefix"), Some(0));
    assert_eq!(graph.get_field_offset("OuterRoot", "node"), Some(8));
    assert_eq!(graph.get_field_offset("OuterRoot", "ptr"), Some(40));
}

// =========================================================================
// 2. AMD64 Layout: Mixed bitfields with signed/unsigned types, boundary overflowing
// =========================================================================
#[test]
fn challenge_mixed_bitfields_and_boundary_overflow() {
    let code = r#"
    struct MixedSignBF {
        signed int s_val : 7;
        unsigned int u_val : 9;
        int remaining : 16;
    };

    struct OverflowBF {
        unsigned short f1 : 10;
        unsigned short f2 : 10;
    };

    struct InterleavedBF {
        int bf1 : 5;
        char middle;
        int bf2 : 6;
    };
    "#;

    let oracle_c = r#"
    #include <stdio.h>
    #include <stddef.h>

    struct MixedSignBF { signed int s_val : 7; unsigned int u_val : 9; int remaining : 16; };
    struct OverflowBF { unsigned short f1 : 10; unsigned short f2 : 10; };
    struct InterleavedBF { int bf1 : 5; char middle; int bf2 : 6; };

    int main() {
        printf("MixedSignBF: size=%zu align=%zu\n", sizeof(struct MixedSignBF), _Alignof(struct MixedSignBF));
        printf("OverflowBF: size=%zu align=%zu\n", sizeof(struct OverflowBF), _Alignof(struct OverflowBF));
        printf("InterleavedBF: size=%zu align=%zu mid_off=%zu\n",
            sizeof(struct InterleavedBF), _Alignof(struct InterleavedBF), offsetof(struct InterleavedBF, middle));
        return 0;
    }
    "#;

    let oracle_out = get_c_compiler_layout(oracle_c).expect("GCC oracle execution failed");
    println!("Oracle Output:\n{}", oracle_out);

    let mut parser = AstParser::new().unwrap();
    let tree = parser.parse_content(code, Path::new("bitfield.c")).unwrap();
    let mut resolver = StructLayoutResolver::new();
    let graph = resolver
        .resolve_struct_layouts(&tree, code, Path::new("bitfield.c"))
        .unwrap();

    let mixed = graph.get_struct("MixedSignBF").expect("MixedSignBF not found");
    assert_eq!(mixed.total_size_bytes, 4);
    assert_eq!(mixed.align_bytes, 4);
    assert_eq!(mixed.fields.len(), 3);
    assert_eq!(mixed.fields[0].bit_width, Some(7));
    assert_eq!(mixed.fields[1].bit_width, Some(9));
    assert_eq!(mixed.fields[2].bit_width, Some(16));

    // OverflowBF: f1 takes 10 bits of 16-bit short. f2 needs 10 bits.
    // 10 + 10 = 20 > 16, so f2 overflows into the next 16-bit storage unit!
    // Total size must be 4 bytes!
    let overflow = graph.get_struct("OverflowBF").expect("OverflowBF not found");
    assert_eq!(overflow.align_bytes, 2);
    assert_eq!(overflow.total_size_bytes, 4, "Bitfield boundary overflow must allocate next storage unit (size 4)");

    let interleaved = graph.get_struct("InterleavedBF").expect("InterleavedBF not found");
    assert_eq!(interleaved.align_bytes, 4);
    assert_eq!(interleaved.total_size_bytes, 12);
    assert_eq!(graph.get_field_offset("InterleavedBF", "middle"), Some(4));
}

// =========================================================================
// 3. AMD64 Layout: Zero-width bitfield boundary alignments
// =========================================================================
#[test]
fn challenge_zero_width_bitfield_boundary_alignment() {
    let code = r#"
    struct ZeroWidthAlign {
        int a : 3;
        int : 0;
        int b : 5;
    };
    "#;

    let oracle_c = r#"
    #include <stdio.h>
    #include <stddef.h>

    struct ZeroWidthAlign {
        int a : 3;
        int : 0;
        int b : 5;
    };

    int main() {
        printf("ZeroWidthAlign: size=%zu align=%zu\n",
            sizeof(struct ZeroWidthAlign), _Alignof(struct ZeroWidthAlign));
        return 0;
    }
    "#;

    let oracle_out = get_c_compiler_layout(oracle_c).expect("GCC oracle execution failed");
    println!("Oracle Output:\n{}", oracle_out);

    let mut parser = AstParser::new().unwrap();
    let tree = parser.parse_content(code, Path::new("zerowidth.c")).unwrap();
    let mut resolver = StructLayoutResolver::new();
    let graph = resolver
        .resolve_struct_layouts(&tree, code, Path::new("zerowidth.c"))
        .unwrap();

    let layout = graph.get_struct("ZeroWidthAlign").expect("ZeroWidthAlign not found");
    println!(
        "Crashwise ZeroWidthAlign resolved size: {}, align: {}",
        layout.total_size_bytes, layout.align_bytes
    );

    // System V AMD64 ABI: Zero-width bitfield forces closure of current allocation unit.
    // 'a' is at unit 0 (offset 0..3), 'b' must be at unit 1 (offset 4..7).
    // Total size must be 8 bytes.
    assert_eq!(
        layout.total_size_bytes, 8,
        "System V AMD64 ABI requires zero-width bitfield (int : 0) to terminate allocation unit, yielding 8 bytes"
    );
    assert_eq!(
        graph.get_field_offset("ZeroWidthAlign", "b"),
        Some(4),
        "Field 'b' must be located at offset 4 in the next storage unit"
    );
}

// =========================================================================
// 4. AMD64 Layout: Multi-dimensional arrays (int arr[3][5])
// =========================================================================
#[test]
fn challenge_multi_dimensional_arrays() {
    let code = r#"
    struct MultiDimMatrix {
        int grid[3][5];
    };

    struct MultiDimWithTail {
        int matrix[2][3];
        double tail;
    };
    "#;

    let oracle_c = r#"
    #include <stdio.h>
    #include <stddef.h>

    struct MultiDimMatrix { int grid[3][5]; };
    struct MultiDimWithTail { int matrix[2][3]; double tail; };

    int main() {
        printf("MultiDimMatrix: size=%zu align=%zu\n",
            sizeof(struct MultiDimMatrix), _Alignof(struct MultiDimMatrix));
        printf("MultiDimWithTail: size=%zu align=%zu tail_off=%zu\n",
            sizeof(struct MultiDimWithTail), _Alignof(struct MultiDimWithTail),
            offsetof(struct MultiDimWithTail, tail));
        return 0;
    }
    "#;

    let oracle_out = get_c_compiler_layout(oracle_c).expect("GCC oracle execution failed");
    println!("Oracle Output:\n{}", oracle_out);

    let mut parser = AstParser::new().unwrap();
    let tree = parser.parse_content(code, Path::new("multidim.c")).unwrap();
    let mut resolver = StructLayoutResolver::new();
    let graph = resolver
        .resolve_struct_layouts(&tree, code, Path::new("multidim.c"))
        .unwrap();

    let matrix = graph.get_struct("MultiDimMatrix").expect("MultiDimMatrix not found");
    println!(
        "Crashwise MultiDimMatrix total_size_bytes: {}",
        matrix.total_size_bytes
    );
    // int grid[3][5] is 3 * 5 * 4 = 60 bytes!
    assert_eq!(
        matrix.total_size_bytes, 60,
        "Multi-dimensional array int grid[3][5] must have total size 3 * 5 * 4 = 60 bytes, not single dimension"
    );

    let with_tail = graph.get_struct("MultiDimWithTail").expect("MultiDimWithTail not found");
    println!(
        "Crashwise MultiDimWithTail total_size_bytes: {}, tail_offset: {:?}",
        with_tail.total_size_bytes,
        graph.get_field_offset("MultiDimWithTail", "tail")
    );
    // int matrix[2][3] is 2 * 3 * 4 = 24 bytes (offsets 0..23).
    // tail is double (align 8), so tail is at offset 24, total size is 32 bytes!
    assert_eq!(
        graph.get_field_offset("MultiDimWithTail", "tail"),
        Some(24),
        "Field 'tail' must be placed at offset 24 after 24-byte 2D matrix"
    );
    assert_eq!(with_tail.total_size_bytes, 32);
}

// =========================================================================
// 5. AMD64 Layout: Typedef alias chains (typedef struct A B; typedef B C;)
// =========================================================================
#[test]
fn challenge_typedef_alias_chains() {
    let code = r#"
    struct Point3D {
        double x;
        double y;
        double z;
    };

    typedef struct Point3D GeoPoint;
    typedef GeoPoint GeoPointAlias1;
    typedef GeoPointAlias1 GeoPointAlias2;

    struct MapMarker {
        int id;
        GeoPointAlias2 position;
    };
    "#;

    let oracle_c = r#"
    #include <stdio.h>
    #include <stddef.h>

    struct Point3D { double x; double y; double z; };
    typedef struct Point3D GeoPoint;
    typedef GeoPoint GeoPointAlias1;
    typedef GeoPointAlias1 GeoPointAlias2;
    struct MapMarker { int id; GeoPointAlias2 position; };

    int main() {
        printf("MapMarker: size=%zu align=%zu pos_off=%zu\n",
            sizeof(struct MapMarker), _Alignof(struct MapMarker),
            offsetof(struct MapMarker, position));
        return 0;
    }
    "#;

    let oracle_out = get_c_compiler_layout(oracle_c).expect("GCC oracle execution failed");
    println!("Oracle Output:\n{}", oracle_out);

    let mut parser = AstParser::new().unwrap();
    let tree = parser.parse_content(code, Path::new("typedef_chain.c")).unwrap();
    let mut resolver = StructLayoutResolver::new();
    let graph = resolver
        .resolve_struct_layouts(&tree, code, Path::new("typedef_chain.c"))
        .unwrap();

    let marker = graph.get_struct("MapMarker").expect("MapMarker not found");
    println!(
        "Crashwise MapMarker size: {}, align: {}, pos_off: {:?}",
        marker.total_size_bytes,
        marker.align_bytes,
        graph.get_field_offset("MapMarker", "position")
    );

    // Point3D is 24 bytes (3 * 8).
    // In MapMarker: id (4) + pad (4) + position (24) = 32 bytes!
    assert_eq!(
        graph.get_field_offset("MapMarker", "position"),
        Some(8),
        "Position field following typedef alias chain must be at offset 8"
    );
    assert_eq!(
        marker.total_size_bytes, 32,
        "Struct referencing typedef alias chain GeoPointAlias2 must resolve Point3D size (24 bytes), total 32 bytes"
    );
}

// =========================================================================
// 6. AMD64 Layout: Function pointer table layouts (vtable simulation)
// =========================================================================
#[test]
fn challenge_function_pointer_vtable_simulation() {
    let code = r#"
    struct DeviceDriverOps {
        int (*open)(void *ctx, int flags);
        int (*read)(void *ctx, char *buf, unsigned long count);
        int (*write)(void *ctx, const char *buf, unsigned long count);
        long (*ioctl)(void *ctx, unsigned int cmd, unsigned long arg);
        void (*close)(void *ctx);
    };
    "#;

    let oracle_c = r#"
    #include <stdio.h>
    #include <stddef.h>

    struct DeviceDriverOps {
        int (*open)(void *ctx, int flags);
        int (*read)(void *ctx, char *buf, unsigned long count);
        int (*write)(void *ctx, const char *buf, unsigned long count);
        long (*ioctl)(void *ctx, unsigned int cmd, unsigned long arg);
        void (*close)(void *ctx);
    };

    int main() {
        printf("DeviceDriverOps: size=%zu align=%zu open=%zu read=%zu write=%zu ioctl=%zu close=%zu\n",
            sizeof(struct DeviceDriverOps), _Alignof(struct DeviceDriverOps),
            offsetof(struct DeviceDriverOps, open),
            offsetof(struct DeviceDriverOps, read),
            offsetof(struct DeviceDriverOps, write),
            offsetof(struct DeviceDriverOps, ioctl),
            offsetof(struct DeviceDriverOps, close));
        return 0;
    }
    "#;

    let oracle_out = get_c_compiler_layout(oracle_c).expect("GCC oracle execution failed");
    println!("Oracle Output:\n{}", oracle_out);

    let mut parser = AstParser::new().unwrap();
    let tree = parser.parse_content(code, Path::new("vtable.c")).unwrap();
    let mut resolver = StructLayoutResolver::new();
    let graph = resolver
        .resolve_struct_layouts(&tree, code, Path::new("vtable.c"))
        .unwrap();

    let vtable = graph.get_struct("DeviceDriverOps").expect("DeviceDriverOps not found");
    assert_eq!(vtable.total_size_bytes, 40);
    assert_eq!(vtable.align_bytes, 8);
    assert_eq!(vtable.fields.len(), 5);

    assert_eq!(graph.get_field_offset("DeviceDriverOps", "open"), Some(0));
    assert_eq!(graph.get_field_offset("DeviceDriverOps", "read"), Some(8));
    assert_eq!(graph.get_field_offset("DeviceDriverOps", "write"), Some(16));
    assert_eq!(graph.get_field_offset("DeviceDriverOps", "ioctl"), Some(24));
    assert_eq!(graph.get_field_offset("DeviceDriverOps", "close"), Some(32));

    for f in &vtable.fields {
        match &f.type_kind {
            TypeKind::FunctionPointer { .. } => {}
            other => panic!("Field {} should be FunctionPointer, got {:?}", f.name, other),
        }
    }
}

// =========================================================================
// 7. AMD64 Layout: Self-referential recursive pointers (linked lists, trees)
// =========================================================================
#[test]
fn challenge_self_referential_recursive_pointers() {
    let code = r#"
    struct AstExpr;
    struct AstStmt;

    struct AstExpr {
        int expr_kind;
        struct AstExpr *lhs;
        struct AstExpr *rhs;
        struct AstStmt *enclosing_stmt;
    };

    struct AstStmt {
        int stmt_kind;
        struct AstExpr *condition;
        struct AstStmt *body;
        struct AstStmt *next;
    };
    "#;

    let oracle_c = r#"
    #include <stdio.h>
    #include <stddef.h>

    struct AstExpr;
    struct AstStmt;
    struct AstExpr { int expr_kind; struct AstExpr *lhs; struct AstExpr *rhs; struct AstStmt *enclosing_stmt; };
    struct AstStmt { int stmt_kind; struct AstExpr *condition; struct AstStmt *body; struct AstStmt *next; };

    int main() {
        printf("AstExpr: size=%zu align=%zu lhs=%zu\n",
            sizeof(struct AstExpr), _Alignof(struct AstExpr), offsetof(struct AstExpr, lhs));
        printf("AstStmt: size=%zu align=%zu cond=%zu\n",
            sizeof(struct AstStmt), _Alignof(struct AstStmt), offsetof(struct AstStmt, condition));
        return 0;
    }
    "#;

    let oracle_out = get_c_compiler_layout(oracle_c).expect("GCC oracle execution failed");
    println!("Oracle Output:\n{}", oracle_out);

    let mut parser = AstParser::new().unwrap();
    let tree = parser.parse_content(code, Path::new("recursive.c")).unwrap();
    let mut resolver = StructLayoutResolver::new();
    let graph = resolver
        .resolve_struct_layouts(&tree, code, Path::new("recursive.c"))
        .unwrap();

    let expr = graph.get_struct("AstExpr").expect("AstExpr not found");
    assert_eq!(expr.total_size_bytes, 32);
    assert_eq!(expr.align_bytes, 8);
    assert_eq!(graph.get_field_offset("AstExpr", "expr_kind"), Some(0));
    assert_eq!(graph.get_field_offset("AstExpr", "lhs"), Some(8));
    assert_eq!(graph.get_field_offset("AstExpr", "rhs"), Some(16));
    assert_eq!(graph.get_field_offset("AstExpr", "enclosing_stmt"), Some(24));

    let stmt = graph.get_struct("AstStmt").expect("AstStmt not found");
    assert_eq!(stmt.total_size_bytes, 32);
    assert_eq!(stmt.align_bytes, 8);
    assert_eq!(graph.get_field_offset("AstStmt", "stmt_kind"), Some(0));
    assert_eq!(graph.get_field_offset("AstStmt", "condition"), Some(8));
    assert_eq!(graph.get_field_offset("AstStmt", "body"), Some(16));
    assert_eq!(graph.get_field_offset("AstStmt", "next"), Some(24));
}

// =========================================================================
// 8. AMD64 Layout: Attribute packed structs (__attribute__((packed)))
// =========================================================================
#[test]
fn challenge_attribute_packed_structs() {
    let code = r#"
    struct __attribute__((packed)) PackedNetworkHeader {
        char version;
        int stream_id;
        short flags;
        long sequence_num;
    };
    "#;

    let oracle_c = r#"
    #include <stdio.h>
    #include <stddef.h>

    struct __attribute__((packed)) PackedNetworkHeader {
        char version;
        int stream_id;
        short flags;
        long sequence_num;
    };

    int main() {
        printf("PackedNetworkHeader: size=%zu align=%zu ver=%zu sid=%zu flg=%zu seq=%zu\n",
            sizeof(struct PackedNetworkHeader), _Alignof(struct PackedNetworkHeader),
            offsetof(struct PackedNetworkHeader, version),
            offsetof(struct PackedNetworkHeader, stream_id),
            offsetof(struct PackedNetworkHeader, flags),
            offsetof(struct PackedNetworkHeader, sequence_num));
        return 0;
    }
    "#;

    let oracle_out = get_c_compiler_layout(oracle_c).expect("GCC oracle execution failed");
    println!("Oracle Output:\n{}", oracle_out);

    let mut parser = AstParser::new().unwrap();
    let tree = parser.parse_content(code, Path::new("packed.c")).unwrap();
    let mut resolver = StructLayoutResolver::new();
    let graph = resolver
        .resolve_struct_layouts(&tree, code, Path::new("packed.c"))
        .unwrap();

    let packed = graph.get_struct("PackedNetworkHeader").expect("PackedNetworkHeader not found");
    assert!(packed.is_packed);
    assert_eq!(packed.align_bytes, 1);
    // 1 (char) + 4 (int) + 2 (short) + 8 (long) = 15 bytes
    assert_eq!(packed.total_size_bytes, 15);
    assert_eq!(graph.get_field_offset("PackedNetworkHeader", "version"), Some(0));
    assert_eq!(graph.get_field_offset("PackedNetworkHeader", "stream_id"), Some(1));
    assert_eq!(graph.get_field_offset("PackedNetworkHeader", "flags"), Some(5));
    assert_eq!(graph.get_field_offset("PackedNetworkHeader", "sequence_num"), Some(7));
}

// =========================================================================
// 9. AMD64 Layout: Union containing nested struct (variant size calculation)
// =========================================================================
#[test]
fn challenge_union_containing_nested_struct() {
    let code = r#"
    union UnionWithNestedStruct {
        struct {
            char header[16];
            int length;
            double checksum;
        } formatted;
        char raw_bytes[8];
    };
    "#;

    let oracle_c = r#"
    #include <stdio.h>
    #include <stddef.h>

    union UnionWithNestedStruct {
        struct {
            char header[16];
            int length;
            double checksum;
        } formatted;
        char raw_bytes[8];
    };

    int main() {
        printf("UnionWithNestedStruct: size=%zu align=%zu\n",
            sizeof(union UnionWithNestedStruct), _Alignof(union UnionWithNestedStruct));
        return 0;
    }
    "#;

    let oracle_out = get_c_compiler_layout(oracle_c).expect("GCC oracle execution failed");
    println!("Oracle Output:\n{}", oracle_out);

    let mut parser = AstParser::new().unwrap();
    let tree = parser.parse_content(code, Path::new("union_nested.c")).unwrap();
    let mut resolver = StructLayoutResolver::new();
    let graph = resolver
        .resolve_struct_layouts(&tree, code, Path::new("union_nested.c"))
        .unwrap();

    let u = graph.get_union("UnionWithNestedStruct").expect("UnionWithNestedStruct not found");
    println!(
        "Crashwise UnionWithNestedStruct: size={}, align={}",
        u.total_size_bytes, u.align_bytes
    );

    // Inner struct formatted: 16 (header) + 4 (length) + 4 (pad) + 8 (checksum) = 32 bytes, align 8.
    // raw_bytes: 32 bytes, align 1.
    // Union total size must be 32 bytes, align 8.
    assert_eq!(
        u.total_size_bytes, 32,
        "Union containing nested struct must calculate variant size from nested struct (32 bytes), not fallback to 8"
    );
    assert_eq!(u.align_bytes, 8);
}

// =========================================================================
// 10. SQLite Feedback Memory: Concurrency and scale (rapid reads/writes)
// =========================================================================
#[test]
fn challenge_sqlite_concurrency_rapid_reads_writes() {
    let db = Arc::new(Database::open_in_memory().expect("Failed to open in-memory SQLite DB"));

    let num_writers = 12;
    let num_readers = 12;
    let ops_per_thread = 50;
    let total_threads = num_writers + num_readers;
    let barrier = Arc::new(Barrier::new(total_threads));

    let mut handles = Vec::new();

    // Spawn writer threads
    for t_idx in 0..num_writers {
        let db_clone = Arc::clone(&db);
        let b_clone = Arc::clone(&barrier);
        handles.push(thread::spawn(move || {
            b_clone.wait();
            for op in 0..ops_per_thread {
                let diag = format!(
                    "error: symbol undefined 'sym_{}_{}' at line {}",
                    t_idx, op, op * 10
                );
                let orig = format!("void fn_{}() {{ bad_call(); }}", op);
                let fix = format!("void fn_{}() {{ good_call(); }}", op);
                let res = db_clone.record_resolved_fix(
                    None,
                    "target_fuzz_x",
                    &diag,
                    &orig,
                    &fix,
                );
                assert!(res.is_ok(), "Concurrent insert failed: {:?}", res.err());
            }
        }));
    }

    // Spawn reader threads
    for _ in 0..num_readers {
        let db_clone = Arc::clone(&db);
        let b_clone = Arc::clone(&barrier);
        handles.push(thread::spawn(move || {
            b_clone.wait();
            for _ in 0..ops_per_thread {
                let fixes = db_clone.query_similar_compiler_fixes(
                    "error: symbol undefined 'sym_0_0'",
                    Some("target_fuzz_x"),
                    5,
                );
                assert!(fixes.is_ok(), "Concurrent query failed: {:?}", fixes.err());
            }
        }));
    }

    for h in handles {
        h.join().expect("Worker thread panicked");
    }

    let all_fixes = db
        .query_similar_compiler_fixes("symbol undefined", Some("target_fuzz_x"), 1000)
        .expect("Final query failed");
    assert_eq!(
        all_fixes.len(),
        num_writers * ops_per_thread,
        "Total inserted records mismatch after concurrent read/write test"
    );
}

// =========================================================================
// 11. SQLite Feedback Memory: Token scoring on large, noisy diagnostic strings
// =========================================================================
#[test]
fn challenge_token_scoring_large_noisy_diagnostic() {
    let db = Database::open_in_memory().expect("Failed to open DB");

    // Insert target exemplars
    let good_fix_id = db
        .record_resolved_fix(
            None,
            "complex_parser",
            "error: unknown type name 'JsonParserConfig' in parser.h:12:4",
            "void init() { JsonParserConfig cfg; }",
            "#include <parser.h>\nvoid init() { JsonParserConfig cfg; }",
        )
        .unwrap();

    let irrelevant_id = db
        .record_resolved_fix(
            None,
            "complex_parser",
            "error: conflicting types for 'realloc' in memory.c:88:1",
            "void *realloc() {}",
            "/* fixed */",
        )
        .unwrap();

    // Construct a massive 60KB noisy compiler diagnostic containing repetitive template dumps and paths
    let mut huge_diag = String::with_capacity(65_536);
    huge_diag.push_str("In file included from src/core/parser.c:4:\n");
    for i in 0..500 {
        huge_diag.push_str(&format!(
            "note: candidate template ignored: could not match 'std::vector<Item_{}>' against 'Span_{}'\n",
            i, i
        ));
        huge_diag.push_str("    with [T = detail::NodeAlloc<int, allocator<int>>, Alloc = void]\n");
    }
    huge_diag.push_str("src/core/parser.c:142:15: error: unknown type name 'JsonParserConfig'\n");
    huge_diag.push_str("    JsonParserConfig *config = NULL;\n");
    huge_diag.push_str("                      ^\n");

    let start = std::time::Instant::now();
    let query_res = db
        .query_similar_compiler_fixes(&huge_diag, Some("complex_parser"), 5)
        .expect("Querying large noisy diagnostic failed");
    let elapsed = start.elapsed();
    println!("Large noisy diagnostic query elapsed: {:?}", elapsed);

    assert!(
        elapsed.as_millis() < 250,
        "Query on large noisy diagnostic took too long: {:?}",
        elapsed
    );
    assert!(!query_res.is_empty(), "Expected match for noisy diagnostic");
    assert_eq!(
        query_res[0].id, good_fix_id,
        "Scoring must rank the exact token match 'JsonParserConfig' as top result"
    );
    assert_ne!(query_res[0].id, irrelevant_id);
}

// =========================================================================
// 12. SQLite Feedback Memory: Edge cases (empty, symbols, unknown target)
// =========================================================================
#[test]
fn challenge_feedback_memory_edge_cases() {
    let db = Database::open_in_memory().expect("Failed to open DB");

    // 1. Empty diagnostic string
    let res_empty = db.query_similar_compiler_fixes("", Some("target_x"), 5);
    assert!(res_empty.is_ok(), "Empty diagnostic string must not panic");
    assert_eq!(res_empty.unwrap().len(), 0);

    // 2. Whitespace-only and symbol-only diagnostics
    let res_ws = db.query_similar_compiler_fixes("   \n\t   ", None, 5);
    assert!(res_ws.is_ok());

    let res_syms = db.query_similar_compiler_fixes("!@#$%^&*()_+-=[]{}|;':\",.<>?/~`", None, 5);
    assert!(res_syms.is_ok());

    // 3. Record fix with empty/symbol strings
    let fix_empty = db.record_resolved_fix(None, "t_empty", "", "", "");
    assert!(fix_empty.is_ok(), "Inserting empty diagnostic fix should succeed");

    // 4. Query unknown target name fallback
    let coverage_toks = db.query_coverage_tokens(Some("non_existent_target"), 10);
    assert!(coverage_toks.is_ok());
    assert_eq!(coverage_toks.unwrap().len(), 0);

    let exemplars = db.query_harness_exemplars(Some("non_existent_target"), 10);
    assert!(exemplars.is_ok());
    assert_eq!(exemplars.unwrap().len(), 0);

    // 5. Query with limit 0
    let res_zero = db.query_similar_compiler_fixes("error: something", None, 0);
    assert!(res_zero.is_ok());
    assert_eq!(res_zero.unwrap().len(), 0);
}
