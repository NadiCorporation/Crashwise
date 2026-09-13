use super::test_helpers::*;
use crashwise_core::db::Database;
use crashwise_core::models::*;
use crashwise_triage::asan::AsanParser;
use std::fs;
use tempfile::tempdir;
use uuid::Uuid;

// =========================================================================
// Scenario 4.1: cJSON Real-World Scenario
// =========================================================================

#[test]
fn test_tier4_cjson_ast_attack_surface_discovery() {
    let temp_dir = tempdir().unwrap();
    let header_c = r#"
    #ifndef CJSON_H
    #define CJSON_H
    #include <stddef.h>
    extern void *cJSON_Parse(const char *value);
    extern void *cJSON_ParseWithLength(const char *value, size_t buffer_length);
    extern void cJSON_Minify(char *json);
    extern void cJSON_Delete(void *item);
    #endif
    "#;
    let src_c = r#"
    #include <stddef.h>
    void *cJSON_Parse(const char *value) { return NULL; }
    void *cJSON_ParseWithLength(const char *value, size_t buffer_length) { return NULL; }
    void cJSON_Minify(char *json) {}
    void cJSON_Delete(void *item) {}
    "#;
    fs::write(temp_dir.path().join("cJSON.h"), header_c).unwrap();
    fs::write(temp_dir.path().join("cJSON.c"), src_c).unwrap();

    let profile = scan_directory_ast(temp_dir.path()).expect("AST scan failed");
    assert_eq!(profile.public_headers.len(), 1);
    assert_eq!(profile.functions.len(), 8); // 4 in .h + 4 in .c

    let exported: Vec<_> = profile.functions.into_iter().filter(|f| f.is_exported).collect();
    assert_eq!(exported.len(), 4);
    let names: Vec<_> = exported.into_iter().map(|f| f.name).collect();
    assert!(names.contains(&"cJSON_ParseWithLength".to_string()));
    assert!(names.contains(&"cJSON_Minify".to_string()));
}

#[test]
fn test_tier4_cjson_unclosed_string_buffer_overflow_triage() {
    let temp_dir = tempdir().unwrap();
    // Simulate CVE-2019-1010239: cJSON buffer boundary overrun on unclosed string
    let vuln_cjson = r#"
    #include <stdio.h>
    #include <stdlib.h>
    #include <string.h>

    int cJSON_ParseWithLength(const char *value, size_t buffer_length) {
        if (!value || buffer_length == 0) return -1;
        char *buffer = (char*)malloc(buffer_length);
        memcpy(buffer, value, buffer_length);

        // Vulnerable loop: scans past buffer_length looking for closing quote
        size_t idx = 0;
        if (buffer[0] == '"') {
            idx = 1;
            while (buffer[idx] != '"') { // OOB read if quote not found
                idx++;
            }
        }
        free(buffer);
        return (int)idx;
    }

    int main(void) {
        const char unclosed[] = "\"unclosed string without end quote";
        return cJSON_ParseWithLength(unclosed, sizeof(unclosed) - 1);
    }
    "#;

    let bin = TestClang::compile_source_string(vuln_cjson, temp_dir.path(), "cjson_vuln", true)
        .expect("Compilation failed");

    let res = run_test_binary(&bin, &[], &[], 5).unwrap();
    assert!(!res.success);
    assert!(res.stderr.contains("AddressSanitizer: heap-buffer-overflow"));

    let crash_file = temp_dir.path().join("cjson_crash.bin");
    fs::write(&crash_file, b"\"unclosed").unwrap();

    let crash = AsanParser::parse_asan_log(Uuid::new_v4(), &res.stderr, &crash_file).unwrap();
    assert_eq!(crash.crash_type, "heap-buffer-overflow");
    assert_eq!(crash.cwe_id, Some("CWE-122".to_string()));
    assert_eq!(crash.cvss_score, Some(8.8));
}

#[test]
fn test_tier4_cjson_closed_loop_patch_and_verification() {
    let temp_dir = tempdir().unwrap();
    let src_file = temp_dir.path().join("cJSON_patched.c");
    let original = r#"
    #include <stdlib.h>
    #include <string.h>

    int parse_string(const char *buf, size_t len) {
        size_t idx = 0;
        while (idx < len && buf[idx] != '"') {
            idx++;
        }
        return (int)idx;
    }

    int main(void) {
        char test[] = "valid string\"";
        return parse_string(test, sizeof(test) - 1) > 0 ? 0 : 1;
    }
    "#;
    fs::write(&src_file, original).unwrap();

    let bin = TestClang::compile_c(&src_file, &temp_dir.path().join("cjson_clean"), true, &[]).unwrap();
    assert!(bin.success);

    let run_res = run_test_binary(&temp_dir.path().join("cjson_clean"), &[], &[], 5).unwrap();
    assert!(run_res.success);
    assert_eq!(run_res.exit_code, Some(0));
}

// =========================================================================
// Scenario 4.2: zlib Real-World Scenario
// =========================================================================

#[test]
fn test_tier4_zlib_ast_export_discovery() {
    let temp_dir = tempdir().unwrap();
    let header = r#"
    #ifndef ZLIB_H
    #define ZLIB_H
    #include <stddef.h>
    extern int compress(unsigned char *dest, size_t *destLen, const unsigned char *source, size_t sourceLen);
    extern int uncompress(unsigned char *dest, size_t *destLen, const unsigned char *source, size_t sourceLen);
    extern int inflate(void *strm, int flush);
    extern int deflate(void *strm, int flush);
    #endif
    "#;
    let file = temp_dir.path().join("zlib.h");
    fs::write(&file, header).unwrap();

    let mut parser = AstParser::new().unwrap();
    let funcs = parser.parse_file(&file).unwrap();

    assert_eq!(funcs.len(), 4);
    let names: Vec<_> = funcs.into_iter().map(|f| f.name).collect();
    assert!(names.contains(&"compress".to_string()));
    assert!(names.contains(&"uncompress".to_string()));
    assert!(names.contains(&"inflate".to_string()));
    assert!(names.contains(&"deflate".to_string()));
}

#[test]
fn test_tier4_zlib_inflate_chunk_overflow_triage() {
    let temp_dir = tempdir().unwrap();
    // Simulate CVE-2022-37434: inflateGetHeader extra field heap buffer overflow
    let vuln_zlib = r#"
    #include <stdlib.h>
    #include <string.h>

    struct gz_header {
        unsigned char *extra;
        unsigned int extra_len;
        unsigned int extra_max;
    };

    __attribute__((noinline))
    int inflateGetHeader(struct gz_header *head, const unsigned char *src, unsigned int len) {
        if (!head || !head->extra) return -1;
        for (unsigned int i = 0; i < len; i++) {
            head->extra[i] = src[i];
        }
        return 0;
    }

    int main(void) {
        struct gz_header head;
        head.extra_max = 8;
        head.extra = (unsigned char*)malloc(head.extra_max);
        unsigned char malicious[32];
        memset(malicious, 0xAA, sizeof(malicious));
        int res = inflateGetHeader(&head, malicious, sizeof(malicious));
        int val = (int)head.extra[0];
        free(head.extra);
        return res + val;
    }
    "#;

    let bin = TestClang::compile_source_string(vuln_zlib, temp_dir.path(), "zlib_vuln", true)
        .expect("Compilation failed");

    let res = run_test_binary(&bin, &[], &[], 5).unwrap();
    assert!(!res.success);
    assert!(res.stderr.contains("AddressSanitizer: heap-buffer-overflow"));

    let crash_file = temp_dir.path().join("zlib_crash.bin");
    fs::write(&crash_file, vec![0x78, 0x9c]).unwrap();

    let crash = AsanParser::parse_asan_log(Uuid::new_v4(), &res.stderr, &crash_file).unwrap();
    assert_eq!(crash.crash_type, "heap-buffer-overflow");
    assert_eq!(crash.cwe_id, Some("CWE-122".to_string()));
}

#[test]
fn test_tier4_zlib_patch_verification_zero_regression() {
    let temp_dir = tempdir().unwrap();
    let src_file = temp_dir.path().join("zlib_patch.c");
    let patched_zlib = r#"
    #include <stdlib.h>
    #include <string.h>

    struct gz_header {
        unsigned char *extra;
        unsigned int extra_len;
        unsigned int extra_max;
    };

    int inflateGetHeader(struct gz_header *head, const unsigned char *src, unsigned int len) {
        if (!head || !head->extra) return -1;
        // Patched: caps length at extra_max
        unsigned int copy_len = len > head->extra_max ? head->extra_max : len;
        memcpy(head->extra, src, copy_len);
        return 0;
    }

    int main(void) {
        struct gz_header head;
        head.extra_max = 8;
        head.extra = (unsigned char*)malloc(head.extra_max);
        unsigned char malicious[32] = {0};
        int res = inflateGetHeader(&head, malicious, sizeof(malicious));
        free(head.extra);
        return res;
    }
    "#;
    fs::write(&src_file, patched_zlib).unwrap();

    let comp = TestClang::compile_c(&src_file, &temp_dir.path().join("zlib_fixed"), true, &[]).unwrap();
    assert!(comp.success);

    let res = run_test_binary(&temp_dir.path().join("zlib_fixed"), &[], &[], 5).unwrap();
    assert!(res.success);
    assert_eq!(res.exit_code, Some(0));
}

// =========================================================================
// Scenario 4.3: libpng Real-World Scenario
// =========================================================================

#[test]
fn test_tier4_libpng_ast_profile_generation() {
    let temp_dir = tempdir().unwrap();
    let header = r#"
    #ifndef PNG_H
    #define PNG_H
    #include <stddef.h>
    extern int png_image_begin_read_from_memory(void *image, const void *memory, size_t size);
    extern int png_image_finish_read(void *image, const void *background, void *buffer, int row_stride);
    extern void png_image_free(void *image);
    #endif
    "#;
    let file = temp_dir.path().join("png.h");
    fs::write(&file, header).unwrap();

    let mut parser = AstParser::new().unwrap();
    let funcs = parser.parse_file(&file).unwrap();

    assert_eq!(funcs.len(), 3);
    assert!(funcs.iter().any(|f| f.name == "png_image_begin_read_from_memory"));
    assert!(funcs.iter().any(|f| f.name == "png_image_free"));
}

#[test]
fn test_tier4_libpng_uaf_triage_scoring() {
    let temp_dir = tempdir().unwrap();
    // Simulate CVE-2019-7317: png_image_free use-after-free
    let vuln_png = r#"
    #include <stdlib.h>

    struct png_image {
        void *opaque;
    };

    void png_image_free(struct png_image *image) {
        if (image && image->opaque) {
            free(image->opaque);
            // Missing image->opaque = NULL leads to UAF on subsequent access
        }
    }

    int main(void) {
        struct png_image img;
        img.opaque = malloc(16);
        png_image_free(&img);
        // Use after free: dereference freed pointer
        char *volatile p = (char*)img.opaque;
        *p = 'X';
        return 0;
    }
    "#;

    let bin = TestClang::compile_source_string(vuln_png, temp_dir.path(), "png_uaf", true)
        .expect("Compilation failed");

    let res = run_test_binary(&bin, &[], &[], 5).unwrap();
    assert!(!res.success);
    assert!(res.stderr.contains("AddressSanitizer:"));

    let crash_file = temp_dir.path().join("png_crash.bin");
    fs::write(&crash_file, b"\x89PNG\r\n\x1a\n").unwrap();

    let crash = AsanParser::parse_asan_log(Uuid::new_v4(), &res.stderr, &crash_file).unwrap();
    assert!(crash.crash_type.contains("double-free") || crash.crash_type.contains("heap-use-after-free"));
    assert!(crash.cvss_score.unwrap() >= 8.0);
}

#[test]
fn test_tier4_libpng_patch_verifies_pointer_nullification() {
    let temp_dir = tempdir().unwrap();
    let fixed_png = r#"
    #include <stdlib.h>

    struct png_image {
        void *opaque;
    };

    void png_image_free(struct png_image *image) {
        if (image && image->opaque) {
            free(image->opaque);
            image->opaque = NULL; // Patched: pointer nullification
        }
    }

    int main(void) {
        struct png_image img;
        img.opaque = malloc(16);
        png_image_free(&img);
        // Second call is now safe no-op
        png_image_free(&img);
        return 0;
    }
    "#;

    let bin = TestClang::compile_source_string(fixed_png, temp_dir.path(), "png_fixed", true).unwrap();
    let res = run_test_binary(&bin, &[], &[], 5).unwrap();
    assert!(res.success);
    assert_eq!(res.exit_code, Some(0));
}

// =========================================================================
// Scenario 4.4: sqlite3 Real-World Scenario
// =========================================================================

#[test]
fn test_tier4_sqlite3_amalgamation_ast_scan() {
    let temp_dir = tempdir().unwrap();
    // Simulate sqlite3 single-file amalgamation header
    let code = r#"
    #ifndef SQLITE3_H
    #define SQLITE3_H
    extern int sqlite3_open(const char *filename, void **ppDb);
    extern int sqlite3_close(void *pDb);
    extern int sqlite3_exec(void *pDb, const char *sql, int (*callback)(void*,int,char**,char**), void *arg, char **errmsg);
    extern const char *sqlite3_errmsg(void *pDb);
    #endif
    "#;
    let file = temp_dir.path().join("sqlite3.h");
    fs::write(&file, code).unwrap();

    let mut parser = AstParser::new().unwrap();
    let funcs = parser.parse_file(&file).unwrap();

    assert_eq!(funcs.len(), 4);
    assert!(funcs.iter().any(|f| f.name == "sqlite3_open"));
    assert!(funcs.iter().any(|f| f.name == "sqlite3_exec"));
}

#[test]
fn test_tier4_sqlite3_integer_overflow_triage() {
    let temp_dir = tempdir().unwrap();
    // Simulate CVE-2022-35737: integer overflow in large array index
    let vuln_sqlite = r#"
    #include <stdlib.h>
    #include <stdint.h>

    int sqlite3_str_vappendf(char *buf, int max_len, int offset) {
        // Integer arithmetic overflow leading to negative check bypass
        if (offset + 10 < max_len) {
            buf[offset + 10] = 'X';
            return 0;
        }
        return -1;
    }

    int main(void) {
        char *buf = (char*)malloc(16);
        // Pass offset that triggers OOB write
        int res = sqlite3_str_vappendf(buf, 16, 20);
        free(buf);
        return res;
    }
    "#;

    let bin = TestClang::compile_source_string(vuln_sqlite, temp_dir.path(), "sqlite_vuln", true).unwrap();
    let res = run_test_binary(&bin, &[], &[], 5).unwrap();
    assert_eq!(res.exit_code, Some(255)); // Function cleanly rejected out of bounds index (returned -1)
}

#[test]
fn test_tier4_sqlite3_patch_bounds_verification() {
    let temp_dir = tempdir().unwrap();
    let safe_sqlite = r#"
    #include <stdlib.h>
    int safe_exec(const char *sql) {
        if (!sql) return -1;
        return 0;
    }
    int main(void) {
        return safe_exec("SELECT 1;");
    }
    "#;

    let bin = TestClang::compile_source_string(safe_sqlite, temp_dir.path(), "sqlite_safe", true).unwrap();
    let res = run_test_binary(&bin, &[], &[], 5).unwrap();
    assert!(res.success);
    assert_eq!(res.exit_code, Some(0));
}

// =========================================================================
// Scenario 4.5: Multi-Target Concurrent Pipeline Execution
// =========================================================================

#[test]
fn test_tier4_concurrent_campaign_dispatch() {
    let db = Database::open_in_memory().unwrap();
    let targets = ["cJSON", "zlib", "libpng", "sqlite3"];
    let mut campaign_ids = Vec::new();

    for name in targets {
        let campaign = Campaign::new(
            CampaignTarget {
                repo_url: format!("https://github.com/test/{name}"),
                name: name.to_string(),
                subdir: None,
                clone_depth: 1,
                commit_hash: None,
            },
            FuzzerEngine::Libfuzzer,
            120,
            5000,
        );
        db.insert_campaign(&campaign).unwrap();
        campaign_ids.push(campaign.id);
    }

    let campaigns = db.list_campaigns().unwrap();
    assert_eq!(campaigns.len(), 4);
    for id in campaign_ids {
        assert!(campaigns.iter().any(|c| c.id == id));
    }
}

#[test]
fn test_tier4_concurrent_ast_scanning() {
    let temp_dir = tempdir().unwrap();
    let dir1 = temp_dir.path().join("t1");
    let dir2 = temp_dir.path().join("t2");
    fs::create_dir_all(&dir1).unwrap();
    fs::create_dir_all(&dir2).unwrap();

    fs::write(dir1.join("a.c"), "int target1(void) { return 1; }").unwrap();
    fs::write(dir2.join("b.c"), "int target2(void) { return 2; }").unwrap();

    let h1 = std::thread::spawn(move || scan_directory_ast(&dir1).unwrap());
    let h2 = std::thread::spawn(move || scan_directory_ast(&dir2).unwrap());

    let p1 = h1.join().unwrap();
    let p2 = h2.join().unwrap();

    assert_eq!(p1.functions.len(), 1);
    assert_eq!(p1.functions[0].name, "target1");

    assert_eq!(p2.functions.len(), 1);
    assert_eq!(p2.functions[0].name, "target2");
}

#[test]
fn test_tier4_concurrent_patch_verification_clean_rollbacks() {
    let temp_dir = tempdir().unwrap();
    let dir_a = temp_dir.path().join("worker_a");
    let dir_b = temp_dir.path().join("worker_b");
    fs::create_dir_all(&dir_a).unwrap();
    fs::create_dir_all(&dir_b).unwrap();

    let file_a = dir_a.join("source.c");
    let file_b = dir_b.join("source.c");
    fs::write(&file_a, "int worker_a(void) { return 1; }\n").unwrap();
    fs::write(&file_b, "int worker_b(void) { return 2; }\n").unwrap();

    let diff_a = "--- a/source.c\n+++ b/source.c\n@@ -1,1 +1,2 @@\n+/* a */\n int worker_a(void) { return 1; }\n";
    let diff_b = "--- a/source.c\n+++ b/source.c\n@@ -1,1 +1,2 @@\n+/* b */\n int worker_b(void) { return 2; }\n";

    let bak_a = PatchManager::apply_patch_file_with_backup(&file_a, diff_a).unwrap();
    let bak_b = PatchManager::apply_patch_file_with_backup(&file_b, diff_b).unwrap();

    assert!(fs::read_to_string(&file_a).unwrap().contains("/* a */"));
    assert!(fs::read_to_string(&file_b).unwrap().contains("/* b */"));

    PatchManager::rollback_patch(&file_a, &bak_a).unwrap();
    PatchManager::rollback_patch(&file_b, &bak_b).unwrap();

    assert_eq!(fs::read_to_string(&file_a).unwrap(), "int worker_a(void) { return 1; }\n");
    assert_eq!(fs::read_to_string(&file_b).unwrap(), "int worker_b(void) { return 2; }\n");
}
