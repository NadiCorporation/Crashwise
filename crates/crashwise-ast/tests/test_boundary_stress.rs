use crashwise_ast::{
    scan_directory_ast, AstParser, StructLayoutResolver, TypeKind,
};
use std::fs;
use std::path::Path;

#[test]
fn test_empty_and_whitespace_translation_units() {
    let mut parser = AstParser::new().expect("Failed to initialize AstParser");
    let mut resolver = StructLayoutResolver::new();

    // 1. Completely empty string
    let empty_tree = parser
        .parse_content("", Path::new("empty.c"))
        .expect("Empty string should parse cleanly");
    let empty_funcs = parser
        .parse_source("", Path::new("empty.c"))
        .expect("Empty source should parse cleanly");
    assert!(empty_funcs.is_empty());

    let empty_graph = resolver
        .resolve_struct_layouts(&empty_tree, "", Path::new("empty.c"))
        .expect("Empty layout resolve should succeed");
    assert!(empty_graph.structs.is_empty());
    assert!(empty_graph.unions.is_empty());
    assert!(empty_graph.typedefs.is_empty());

    // 2. Whitespace, newlines, tabs
    let ws_content = "   \t\t\n\r\n   \n   \t  ";
    let ws_tree = parser
        .parse_content(ws_content, Path::new("ws.c"))
        .expect("Whitespace string should parse cleanly");
    let ws_funcs = parser
        .parse_source(ws_content, Path::new("ws.c"))
        .expect("Whitespace source should parse cleanly");
    assert!(ws_funcs.is_empty());

    let ws_graph = resolver
        .resolve_struct_layouts(&ws_tree, ws_content, Path::new("ws.c"))
        .expect("Whitespace layout resolve should succeed");
    assert!(ws_graph.structs.is_empty());

    // 3. Comments only
    let comments_content = r#"
    // Single line comment
    /* Multi-line comment
       spanning multiple lines
    */
    /**
     * Doxygen style comment
     */
    "#;
    let comment_tree = parser
        .parse_content(comments_content, Path::new("comments.h"))
        .expect("Comments should parse cleanly");
    let comment_funcs = parser
        .parse_source(comments_content, Path::new("comments.h"))
        .expect("Comments should parse cleanly");
    assert!(comment_funcs.is_empty());

    let comment_graph = resolver
        .resolve_struct_layouts(&comment_tree, comments_content, Path::new("comments.h"))
        .expect("Comment layout resolve should succeed");
    assert!(comment_graph.structs.is_empty());
}

#[test]
fn test_malformed_syntax_and_missing_braces() {
    let mut parser = AstParser::new().expect("Failed to initialize AstParser");
    let mut resolver = StructLayoutResolver::new();

    // 1. Missing closing brace in struct declaration
    let unclosed_struct = r#"
    struct Unclosed {
        int a;
        double b;
    "#;
    let tree1 = parser
        .parse_content(unclosed_struct, Path::new("unclosed.c"))
        .expect("Tree-sitter should parse unclosed struct with ERROR recovery");
    let res1 = resolver.resolve_struct_layouts(&tree1, unclosed_struct, Path::new("unclosed.c"));
    assert!(res1.is_ok(), "Resolver should handle unclosed struct without panic");

    // 2. Missing opening brace
    let missing_open = r#"
    struct MissingOpen
        int x;
        int y;
    };
    "#;
    let tree2 = parser
        .parse_content(missing_open, Path::new("missing_open.c"))
        .expect("Tree-sitter should parse missing open brace with ERROR recovery");
    let res2 = resolver.resolve_struct_layouts(&tree2, missing_open, Path::new("missing_open.c"));
    assert!(res2.is_ok(), "Resolver should handle missing open brace without panic");

    // 3. Missing semicolons
    let missing_semi = r#"
    struct NoSemi {
        int a
        int b
    }
    "#;
    let tree3 = parser
        .parse_content(missing_semi, Path::new("no_semi.c"))
        .expect("Tree-sitter should parse missing semicolons");
    let res3 = resolver.resolve_struct_layouts(&tree3, missing_semi, Path::new("no_semi.c"));
    assert!(res3.is_ok());

    // 4. Unterminated string literal inside function
    let unterminated_str = r#"
    void broken_func(void) {
        char *str = "unterminated string literal without closing quote;
        int next_statement = 42;
    }
    void valid_func(int x) {
        int y = x + 1;
    }
    "#;
    let funcs = parser
        .parse_source(unterminated_str, Path::new("unterminated.c"))
        .expect("Parser should recover from unterminated strings");
    // valid_func should still be recovered
    assert!(funcs.iter().any(|f| f.name == "valid_func" || f.name == "broken_func"));

    // 5. Random junk / garbage tokens
    let garbage = r#"
    #$@%^&*!~`
    @#%
    struct ValidAfterGarbage {
        int id;
        void *ptr;
    };
    !@#$%^&*()_+|}{":?><
    "#;
    let tree_garbage = parser
        .parse_content(garbage, Path::new("garbage.c"))
        .expect("Garbage tokens should not cause parser crash");
    let res_garbage = resolver.resolve_struct_layouts(&tree_garbage, garbage, Path::new("garbage.c"));
    assert!(res_garbage.is_ok(), "Resolver must gracefully return Ok without panic on pure garbage");

    // Syntax error followed by valid struct
    let recovered_code = r#"
    int broken_syntax( {
        ???
    }
    struct RecoveredStruct {
        int id;
        double value;
    };
    "#;
    let tree_rec = parser
        .parse_content(recovered_code, Path::new("recovered.c"))
        .expect("Recovered code should parse");
    let graph_rec = resolver
        .resolve_struct_layouts(&tree_rec, recovered_code, Path::new("recovered.c"))
        .expect("Resolver should handle recovered code");
    assert!(
        graph_rec.get_struct("RecoveredStruct").is_some(),
        "Should recover RecoveredStruct after function syntax error"
    );



    // 6. Highly nested unmatched braces
    let deep_braces = "{{{{{{{{{{ struct NestedInBraces { int val; }; }}}}}}}}}}";
    let tree_braces = parser
        .parse_content(deep_braces, Path::new("braces.c"))
        .expect("Deep braces should parse");
    let graph_braces = resolver
        .resolve_struct_layouts(&tree_braces, deep_braces, Path::new("braces.c"))
        .expect("Deep braces should resolve");
    assert!(graph_braces.get_struct("NestedInBraces").is_some());
}

#[test]
fn test_incomplete_and_forward_struct_declarations() {
    let mut parser = AstParser::new().expect("Failed to initialize AstParser");
    let mut resolver = StructLayoutResolver::new();

    let code = r#"
    // Forward declaration of opaque type
    struct OpaqueContext;
    typedef struct OpaqueContext OpaqueContext_t;

    // Struct referencing opaque pointer
    struct Consumer {
        int id;
        struct OpaqueContext *ctx;
        OpaqueContext_t *t_ctx;
        size_t buffer_size;
    };

    // Self-referential doubly linked list
    struct ListNode {
        int key;
        int value;
        struct ListNode *prev;
        struct ListNode *next;
    };

    // Mutually recursive structs
    struct NodeA;
    struct NodeB;

    struct NodeA {
        int type_a;
        struct NodeB *b_ptr;
    };

    struct NodeB {
        int type_b;
        struct NodeA *a_ptr;
    };
    "#;

    let tree = parser
        .parse_content(code, Path::new("opaque.c"))
        .expect("Failed to parse opaque code");
    let graph = resolver
        .resolve_struct_layouts(&tree, code, Path::new("opaque.c"))
        .expect("Failed to resolve struct layouts");

    // 1. Consumer layout
    let consumer = graph.get_struct("Consumer").expect("Consumer not found");
    assert_eq!(consumer.align_bytes, 8);
    assert_eq!(graph.get_field_offset("Consumer", "id"), Some(0));
    assert_eq!(graph.get_field_offset("Consumer", "ctx"), Some(8));
    assert_eq!(graph.get_field_offset("Consumer", "t_ctx"), Some(16));
    assert_eq!(graph.get_field_offset("Consumer", "buffer_size"), Some(24));
    assert_eq!(consumer.total_size_bytes, 32);

    // 2. ListNode layout
    let node = graph.get_struct("ListNode").expect("ListNode not found");
    assert_eq!(node.align_bytes, 8);
    assert_eq!(graph.get_field_offset("ListNode", "key"), Some(0));
    assert_eq!(graph.get_field_offset("ListNode", "value"), Some(4));
    assert_eq!(graph.get_field_offset("ListNode", "prev"), Some(8));
    assert_eq!(graph.get_field_offset("ListNode", "next"), Some(16));
    assert_eq!(node.total_size_bytes, 24);

    // 3. Mutually recursive structs
    let na = graph.get_struct("NodeA").expect("NodeA not found");
    let nb = graph.get_struct("NodeB").expect("NodeB not found");
    assert_eq!(na.total_size_bytes, 16);
    assert_eq!(nb.total_size_bytes, 16);
}

#[test]
fn test_multiline_macros_and_preprocessor_constructs() {
    let mut parser = AstParser::new().expect("Failed to initialize AstParser");
    let mut resolver = StructLayoutResolver::new();

    let code = r#"
    #ifndef MACRO_TEST_H
    #define MACRO_TEST_H

    #define DECLARE_MODULE(name) \
        typedef struct name##_Module { \
            int id; \
            const char *module_name; \
        } name##_Module;

    #define CHECK(cond) \
        do { \
            if (!(cond)) return -1; \
        } while (0)

    #ifdef __cplusplus
    extern "C" {
    #endif

    typedef struct HeaderWithGuards {
        unsigned int magic;
        unsigned short version;
        unsigned short flags;
    } HeaderWithGuards;

    int parse_header(const HeaderWithGuards *hdr);
    void dump_header(const HeaderWithGuards *hdr);

    #ifdef __cplusplus
    }
    #endif

    #endif // MACRO_TEST_H
    "#;

    let tree = parser
        .parse_content(code, Path::new("macro_test.h"))
        .expect("Macro code should parse");
    let graph = resolver
        .resolve_struct_layouts(&tree, code, Path::new("macro_test.h"))
        .expect("Layout should resolve");

    let hdr = graph
        .get_struct("HeaderWithGuards")
        .expect("HeaderWithGuards struct not found");
    assert_eq!(hdr.align_bytes, 4);
    assert_eq!(graph.get_field_offset("HeaderWithGuards", "magic"), Some(0));
    assert_eq!(graph.get_field_offset("HeaderWithGuards", "version"), Some(4));
    assert_eq!(graph.get_field_offset("HeaderWithGuards", "flags"), Some(6));
    assert_eq!(hdr.total_size_bytes, 8);

    let funcs = parser
        .parse_source(code, Path::new("macro_test.h"))
        .expect("Header functions should parse");
    assert!(funcs.iter().any(|f| f.name == "parse_header"));
    assert!(funcs.iter().any(|f| f.name == "dump_header"));
}

#[test]
fn test_obscure_c_keywords_and_extensions() {
    let mut parser = AstParser::new().expect("Failed to initialize AstParser");
    let mut resolver = StructLayoutResolver::new();

    let code = r#"
    struct __attribute__((packed)) PackedAttrib {
        char tag;
        int val;
        char flag;
    };

    struct ModifiersTest {
        const volatile int status;
        void * restrict ptr;
        _Atomic int atomic_counter;
    };

    struct BitfieldVariations {
        unsigned int bit1 : 1;
        unsigned int bit2 : 1;
        unsigned int : 0; // zero-width bitfield
        unsigned int bit3 : 2;
        int count;
    };

    struct FlexibleArray {
        int length;
        char data[];
    };

    struct ZeroLengthArray {
        int count;
        int items[0];
    };
    "#;

    let tree = parser
        .parse_content(code, Path::new("obscure.c"))
        .expect("Obscure keywords should parse");
    let graph = resolver
        .resolve_struct_layouts(&tree, code, Path::new("obscure.c"))
        .expect("Obscure keywords layout resolve should succeed");

    // 1. Packed attribute layout
    let packed = graph.get_struct("PackedAttrib").expect("PackedAttrib not found");
    assert!(packed.is_packed);
    assert_eq!(packed.total_size_bytes, 6); // 1 + 4 + 1
    assert_eq!(packed.align_bytes, 1);
    assert_eq!(graph.get_field_offset("PackedAttrib", "tag"), Some(0));
    assert_eq!(graph.get_field_offset("PackedAttrib", "val"), Some(1));
    assert_eq!(graph.get_field_offset("PackedAttrib", "flag"), Some(5));

    // 2. Modifiers layout
    let mod_struct = graph.get_struct("ModifiersTest").expect("ModifiersTest not found");
    assert_eq!(mod_struct.align_bytes, 8);
    assert_eq!(graph.get_field_offset("ModifiersTest", "status"), Some(0));
    assert_eq!(graph.get_field_offset("ModifiersTest", "ptr"), Some(8));
    assert_eq!(graph.get_field_offset("ModifiersTest", "atomic_counter"), Some(16));

    // 3. Bitfield variations
    let bf = graph.get_struct("BitfieldVariations").expect("BitfieldVariations not found");
    assert_eq!(bf.align_bytes, 4);

    // 4. Flexible and zero length arrays
    let _fam = graph.get_struct("FlexibleArray").expect("FlexibleArray not found");
    assert_eq!(graph.get_field_offset("FlexibleArray", "length"), Some(0));

    let _zla = graph.get_struct("ZeroLengthArray").expect("ZeroLengthArray not found");
    assert_eq!(graph.get_field_offset("ZeroLengthArray", "count"), Some(0));
}

#[test]
fn test_deep_pointer_and_function_pointer_tables() {
    let mut parser = AstParser::new().expect("Failed to initialize AstParser");
    let mut resolver = StructLayoutResolver::new();

    let code = r#"
    // Deep pointer chain
    struct DeepPointers {
        int *p1;
        int **p2;
        int ***p3;
        int ****p4;
        int *****p5;
        void **********deep_void;
    };

    // Deep function pointer declarations and virtual table
    struct DriverOperations {
        int (*open)(const char *path, int flags, int mode);
        int (*close)(int fd);
        long (*read)(int fd, void *buf, size_t count);
        long (*write)(int fd, const void *buf, size_t count);
        int (*ioctl)(int fd, unsigned int cmd, unsigned long arg);
        void *(*mmap)(void *addr, size_t length, int prot, int flags, int fd, long offset);
        int (**indirect_callback_table)(int event_id);
    };

    // Function taking function pointer parameter and returning pointer
    typedef void (*callback_t)(int status, void *user_data);
    callback_t register_callback(int id, callback_t cb);
    "#;

    let tree = parser
        .parse_content(code, Path::new("deep_ptrs.c"))
        .expect("Deep pointers should parse");
    let graph = resolver
        .resolve_struct_layouts(&tree, code, Path::new("deep_ptrs.c"))
        .expect("Deep pointers layout resolve should succeed");

    // 1. Deep pointers layout
    let deep = graph.get_struct("DeepPointers").expect("DeepPointers not found");
    assert_eq!(deep.align_bytes, 8);
    assert_eq!(deep.total_size_bytes, 48); // 6 pointers * 8 bytes
    assert_eq!(graph.get_field_offset("DeepPointers", "p1"), Some(0));
    assert_eq!(graph.get_field_offset("DeepPointers", "p2"), Some(8));
    assert_eq!(graph.get_field_offset("DeepPointers", "p3"), Some(16));
    assert_eq!(graph.get_field_offset("DeepPointers", "p4"), Some(24));
    assert_eq!(graph.get_field_offset("DeepPointers", "p5"), Some(32));
    assert_eq!(graph.get_field_offset("DeepPointers", "deep_void"), Some(40));

    // Verify indirection in TypeKind
    if let TypeKind::Pointer { indirection, .. } = &deep.fields[4].type_kind {
        assert_eq!(*indirection, 5);
    } else {
        panic!("Expected Pointer with indirection 5");
    }

    // 2. DriverOperations vtable layout
    let ops = graph.get_struct("DriverOperations").expect("DriverOperations not found");
    assert_eq!(ops.align_bytes, 8);
    assert_eq!(ops.total_size_bytes, 56); // 7 function pointers * 8 bytes
    assert_eq!(graph.get_field_offset("DriverOperations", "open"), Some(0));
    assert_eq!(graph.get_field_offset("DriverOperations", "close"), Some(8));
    assert_eq!(graph.get_field_offset("DriverOperations", "read"), Some(16));
    assert_eq!(graph.get_field_offset("DriverOperations", "write"), Some(24));
    assert_eq!(graph.get_field_offset("DriverOperations", "ioctl"), Some(32));
    assert_eq!(graph.get_field_offset("DriverOperations", "mmap"), Some(40));
    assert_eq!(graph.get_field_offset("DriverOperations", "indirect_callback_table"), Some(48));

    // 3. Exported function returning function pointer
    let funcs = parser
        .parse_source(code, Path::new("deep_ptrs.h"))
        .expect("Header should parse");
    let reg_fn = funcs
        .iter()
        .find(|f| f.name == "register_callback")
        .expect("register_callback function signature not found");
    assert!(reg_fn.is_exported);
}

#[test]
fn test_directory_scanner_with_real_world_headers() {
    let temp_dir = tempfile::tempdir().expect("Failed to create tempdir");

    // Copy real-world zlib.h from /usr/include/zlib.h if available
    if Path::new("/usr/include/zlib.h").exists() {
        let zlib_content = fs::read_to_string("/usr/include/zlib.h").expect("Read zlib.h");
        fs::write(temp_dir.path().join("zlib.h"), &zlib_content).expect("Write zlib.h");
    }

    // Create realistic cJSON.h
    let cjson_h = r#"
    #ifndef cJSON__h
    #define cJSON__h

    #define cJSON_Invalid (0)
    #define cJSON_False  (1 << 0)
    #define cJSON_True   (1 << 1)
    #define cJSON_NULL   (1 << 2)
    #define cJSON_Number (1 << 3)
    #define cJSON_String (1 << 4)
    #define cJSON_Array  (1 << 5)
    #define cJSON_Object (1 << 6)
    #define cJSON_Raw    (1 << 7)

    typedef struct cJSON {
        struct cJSON *next;
        struct cJSON *prev;
        struct cJSON *child;
        int type;
        char *valuestring;
        int valueint;
        double valuedouble;
        char *string;
    } cJSON;

    typedef struct cJSON_Hooks {
        void *(*malloc_fn)(size_t sz);
        void (*free_fn)(void *ptr);
    } cJSON_Hooks;

    const char *cJSON_Version(void);
    void cJSON_InitHooks(cJSON_Hooks* hooks);
    cJSON *cJSON_Parse(const char *value);
    cJSON *cJSON_ParseWithLength(const char *value, size_t buffer_length);
    char *cJSON_Print(const cJSON *item);
    char *cJSON_PrintUnformatted(const cJSON *item);
    void cJSON_Delete(cJSON *item);
    int cJSON_GetArraySize(const cJSON *array);
    cJSON *cJSON_GetArrayItem(const cJSON *array, int index);
    cJSON *cJSON_GetObjectItem(const cJSON * const object, const char * const string);

    #endif
    "#;
    fs::write(temp_dir.path().join("cJSON.h"), cjson_h).expect("Write cJSON.h");

    // Create cJSON.c with dangerous sinks
    let cjson_c = r#"
    #include "cJSON.h"
    #include <stdlib.h>
    #include <string.h>

    static cJSON_Hooks global_hooks = { malloc, free };

    cJSON *cJSON_Parse(const char *value) {
        if (!value) return NULL;
        cJSON *item = (cJSON*)malloc(sizeof(cJSON));
        if (!item) return NULL;
        memset(item, 0, sizeof(cJSON));
        item->valuestring = (char*)malloc(strlen(value) + 1);
        if (item->valuestring) {
            strcpy(item->valuestring, value);
        }
        return item;
    }

    void cJSON_Delete(cJSON *item) {
        if (item) {
            if (item->valuestring) {
                free(item->valuestring);
            }
            free(item);
        }
    }
    "#;
    fs::write(temp_dir.path().join("cJSON.c"), cjson_c).expect("Write cJSON.c");

    // Scan directory
    let profile = scan_directory_ast(temp_dir.path()).expect("scan_directory_ast failed");

    // Assert public headers detected
    assert!(profile.public_headers.iter().any(|p| p.ends_with("cJSON.h")));
    if Path::new("/usr/include/zlib.h").exists() {
        assert!(profile.public_headers.iter().any(|p| p.ends_with("zlib.h")));
    }

    // Assert cJSON struct extracted
    let cjson_struct = profile
        .structs
        .iter()
        .find(|s| s.name == "cJSON")
        .expect("cJSON struct not found in profile");
    assert_eq!(cjson_struct.fields.len(), 8);
    assert_eq!(cjson_struct.total_size_bytes, 64); // AMD64 struct layout
    assert_eq!(cjson_struct.align_bytes, 8);

    // Assert exported functions
    let parse_fn = profile
        .functions
        .iter()
        .find(|f| f.name == "cJSON_Parse")
        .expect("cJSON_Parse function not found");
    assert!(parse_fn.is_exported);

    // Assert dangerous sinks in cJSON.c
    let malloc_sink = profile
        .dangerous_sinks
        .iter()
        .find(|s| s.sink_type == "malloc" && s.function_name == "cJSON_Parse");
    assert!(malloc_sink.is_some(), "malloc sink should be detected in cJSON_Parse");

    let free_sink = profile
        .dangerous_sinks
        .iter()
        .find(|s| s.sink_type == "free" && s.function_name == "cJSON_Delete");
    assert!(free_sink.is_some(), "free sink should be detected in cJSON_Delete");

    let strcpy_sink = profile
        .dangerous_sinks
        .iter()
        .find(|s| s.sink_type == "strcpy" && s.function_name == "cJSON_Parse");
    assert!(strcpy_sink.is_some(), "strcpy sink should be detected in cJSON_Parse");
}

#[test]
fn test_directory_scanner_resilience_binary_and_corrupt_files() {
    let temp_dir = tempfile::tempdir().expect("Failed to create tempdir");

    // 1. Binary file pretending to be a header
    let binary_bytes: Vec<u8> = vec![
        0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A, // PNG header
        0x00, 0x00, 0x00, 0x0D, 0x49, 0x48, 0x44, 0x52,
        0xFF, 0xFE, 0xFD, 0xFC, 0x00, 0x00, 0x00, 0x00,
    ];
    fs::write(temp_dir.path().join("fake_binary.h"), binary_bytes).unwrap();

    // 2. Corrupt/malformed C file with null bytes and invalid UTF-8
    let corrupt_bytes: Vec<u8> = vec![0x76, 0x6F, 0x69, 0x64, 0x20, 0x66, 0x28, 0x29, 0x7B, 0xFF, 0xFE, 0x00];
    fs::write(temp_dir.path().join("corrupt.c"), corrupt_bytes).unwrap();

    // 3. Valid header next to corrupt files
    let valid_h = r#"
    typedef struct ValidModel {
        int id;
        double score;
    } ValidModel;
    "#;
    fs::write(temp_dir.path().join("valid.h"), valid_h).unwrap();

    // 4. Run directory scan - MUST NOT PANIC OR ABORT
    let profile = scan_directory_ast(temp_dir.path()).expect("scan_directory_ast must not crash on corrupt files");

    // Valid header should still be parsed despite corrupt files
    assert!(profile.structs.iter().any(|s| s.name == "ValidModel"));
    let valid_struct = profile.structs.iter().find(|s| s.name == "ValidModel").unwrap();
    assert_eq!(valid_struct.total_size_bytes, 16);
    assert_eq!(valid_struct.align_bytes, 8);
}
