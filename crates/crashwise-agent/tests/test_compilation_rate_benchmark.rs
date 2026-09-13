use crashwise_agent::HarnessSynthesizer;
use crashwise_ast::types::{FunctionSignature, ParameterInfo};
use std::path::{Path, PathBuf};
use std::process::Command;
use tempfile::tempdir;

struct BenchmarkCase {
    target_name: &'static str,
    header_name: &'static str,
    func: FunctionSignature,
}

fn create_benchmark_headers(include_dir: &Path) {
    // 1. cJSON.h
    let cjson_h = r#"#ifndef CJSON_H
#define CJSON_H
#include <stddef.h>
#include <stdint.h>
#ifdef __cplusplus
extern "C" {
#endif
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

cJSON *cJSON_Parse(const char *value);
cJSON *cJSON_ParseWithLength(const char *value, size_t buffer_length);
char *cJSON_Print(const cJSON *item);
char *cJSON_PrintUnformatted(const cJSON *item);
void cJSON_Delete(cJSON *item);
#ifdef __cplusplus
}
#endif
#endif
"#;
    std::fs::write(include_dir.join("cJSON.h"), cjson_h).unwrap();

    // 2. zlib.h
    let zlib_h = r#"#ifndef ZLIB_H
#define ZLIB_H
#include <stddef.h>
#include <stdint.h>
#ifdef __cplusplus
extern "C" {
#endif
typedef unsigned char Bytef;
typedef unsigned long uLongf;
typedef unsigned long uLong;

typedef struct z_stream_s {
    Bytef *next_in;
    uLong avail_in;
    uLong total_in;
    Bytef *next_out;
    uLong avail_out;
    uLong total_out;
    const char *msg;
    void *state;
} z_stream;
typedef z_stream *z_streamp;

int compress(Bytef *dest, uLongf *destLen, const Bytef *source, uLong sourceLen);
int uncompress(Bytef *dest, uLongf *destLen, const Bytef *source, uLong sourceLen);
int deflate(z_streamp strm, int flush);
int inflate(z_streamp strm, int flush);
#ifdef __cplusplus
}
#endif
#endif
"#;
    std::fs::write(include_dir.join("zlib.h"), zlib_h).unwrap();

    // 3. sqlite3.h
    let sqlite3_h = r#"#ifndef SQLITE3_H
#define SQLITE3_H
#include <stddef.h>
#ifdef __cplusplus
extern "C" {
#endif
typedef struct sqlite3 sqlite3;
int sqlite3_open(const char *filename, sqlite3 **ppDb);
int sqlite3_close(sqlite3 *db);
int sqlite3_exec(sqlite3 *db, const char *sql, int (*callback)(void*,int,char**,char**), void *arg, char **errmsg);
#ifdef __cplusplus
}
#endif
#endif
"#;
    std::fs::write(include_dir.join("sqlite3.h"), sqlite3_h).unwrap();

    // 4. png.h
    let png_h = r#"#ifndef PNG_H
#define PNG_H
#include <stddef.h>
#ifdef __cplusplus
extern "C" {
#endif
typedef const char *png_const_charp;
typedef void *png_voidp;
typedef void (*png_error_ptr)(void *, const char *);
typedef struct png_struct_def png_struct;
typedef png_struct *png_structp;
typedef png_struct *png_structrp;

png_structp png_create_read_struct(png_const_charp user_png_ver, png_voidp error_ptr, png_error_ptr error_fn, png_error_ptr warn_fn);
void png_set_sig_bytes(png_structrp png_ptr, int num_bytes);
#ifdef __cplusplus
}
#endif
#endif
"#;
    std::fs::write(include_dir.join("png.h"), png_h).unwrap();
}

fn build_stubs_library(include_dir: &Path, lib_dir: &Path) -> PathBuf {
    let stub_c = r#"
#include "cJSON.h"
#include "zlib.h"
#include "sqlite3.h"
#include "png.h"
#include <stdlib.h>

cJSON *cJSON_Parse(const char *value) { (void)value; return NULL; }
cJSON *cJSON_ParseWithLength(const char *value, size_t len) { (void)value; (void)len; return NULL; }
char *cJSON_Print(const cJSON *item) { (void)item; return NULL; }
char *cJSON_PrintUnformatted(const cJSON *item) { (void)item; return NULL; }
void cJSON_Delete(cJSON *item) { (void)item; }

int compress(Bytef *dest, uLongf *destLen, const Bytef *source, uLong sourceLen) { (void)dest; (void)destLen; (void)source; (void)sourceLen; return 0; }
int uncompress(Bytef *dest, uLongf *destLen, const Bytef *source, uLong sourceLen) { (void)dest; (void)destLen; (void)source; (void)sourceLen; return 0; }
int deflate(z_streamp strm, int flush) { (void)strm; (void)flush; return 0; }
int inflate(z_streamp strm, int flush) { (void)strm; (void)flush; return 0; }

int sqlite3_open(const char *filename, sqlite3 **ppDb) { (void)filename; if (ppDb) *ppDb = NULL; return 0; }
int sqlite3_close(sqlite3 *db) { (void)db; return 0; }
int sqlite3_exec(sqlite3 *db, const char *sql, int (*callback)(void*,int,char**,char**), void *arg, char **errmsg) { (void)db; (void)sql; (void)callback; (void)arg; (void)errmsg; return 0; }

png_structp png_create_read_struct(png_const_charp user_png_ver, png_voidp error_ptr, png_error_ptr error_fn, png_error_ptr warn_fn) { (void)user_png_ver; (void)error_ptr; (void)error_fn; (void)warn_fn; return NULL; }
void png_set_sig_bytes(png_structrp png_ptr, int num_bytes) { (void)png_ptr; (void)num_bytes; }
"#;

    let src_path = lib_dir.join("stubs.c");
    let obj_path = lib_dir.join("stubs.o");
    let lib_path = lib_dir.join("libtarget_stubs.a");

    std::fs::write(&src_path, stub_c).unwrap();

    let compile_status = Command::new("clang")
        .arg("-c")
        .arg(&src_path)
        .arg("-I")
        .arg(include_dir)
        .arg("-o")
        .arg(&obj_path)
        .status()
        .expect("Failed to invoke clang for stub object");
    assert!(compile_status.success());

    let ar_status = Command::new("ar")
        .arg("rcs")
        .arg(&lib_path)
        .arg(&obj_path)
        .status()
        .expect("Failed to invoke ar for stub library");
    assert!(ar_status.success());

    lib_path
}

#[tokio::test]
async fn test_first_attempt_compilation_success_exceeds_80_percent() {
    let temp = tempdir().expect("Failed to create tempdir");
    let include_dir = temp.path().join("include");
    std::fs::create_dir_all(&include_dir).unwrap();
    let out_dir = temp.path().join("build");
    std::fs::create_dir_all(&out_dir).unwrap();

    create_benchmark_headers(&include_dir);
    let lib_path = build_stubs_library(&include_dir, &out_dir);

    let test_suite: Vec<BenchmarkCase> = vec![
        BenchmarkCase {
            target_name: "cJSON",
            header_name: "cJSON.h",
            func: FunctionSignature {
                name: "cJSON_Parse".to_string(),
                return_type: "cJSON *".to_string(),
                parameters: vec![ParameterInfo {
                    name: "value".to_string(),
                    type_name: "char".to_string(),
                    is_pointer: true,
                    is_const: true,
                }],
                file_path: PathBuf::from("cJSON.c"),
                line_number: 10,
                is_static: false,
                is_exported: true,
                has_body: true,
            },
        },
        BenchmarkCase {
            target_name: "cJSON",
            header_name: "cJSON.h",
            func: FunctionSignature {
                name: "cJSON_ParseWithLength".to_string(),
                return_type: "cJSON *".to_string(),
                parameters: vec![
                    ParameterInfo {
                        name: "value".to_string(),
                        type_name: "char".to_string(),
                        is_pointer: true,
                        is_const: true,
                    },
                    ParameterInfo {
                        name: "buffer_length".to_string(),
                        type_name: "size_t".to_string(),
                        is_pointer: false,
                        is_const: false,
                    },
                ],
                file_path: PathBuf::from("cJSON.c"),
                line_number: 20,
                is_static: false,
                is_exported: true,
                has_body: true,
            },
        },
        BenchmarkCase {
            target_name: "cJSON",
            header_name: "cJSON.h",
            func: FunctionSignature {
                name: "cJSON_Print".to_string(),
                return_type: "char *".to_string(),
                parameters: vec![ParameterInfo {
                    name: "item".to_string(),
                    type_name: "cJSON".to_string(),
                    is_pointer: true,
                    is_const: true,
                }],
                file_path: PathBuf::from("cJSON.c"),
                line_number: 30,
                is_static: false,
                is_exported: true,
                has_body: true,
            },
        },
        BenchmarkCase {
            target_name: "cJSON",
            header_name: "cJSON.h",
            func: FunctionSignature {
                name: "cJSON_PrintUnformatted".to_string(),
                return_type: "char *".to_string(),
                parameters: vec![ParameterInfo {
                    name: "item".to_string(),
                    type_name: "cJSON".to_string(),
                    is_pointer: true,
                    is_const: true,
                }],
                file_path: PathBuf::from("cJSON.c"),
                line_number: 40,
                is_static: false,
                is_exported: true,
                has_body: true,
            },
        },
        BenchmarkCase {
            target_name: "zlib",
            header_name: "zlib.h",
            func: FunctionSignature {
                name: "compress".to_string(),
                return_type: "int".to_string(),
                parameters: vec![
                    ParameterInfo {
                        name: "dest".to_string(),
                        type_name: "Bytef".to_string(),
                        is_pointer: true,
                        is_const: false,
                    },
                    ParameterInfo {
                        name: "destLen".to_string(),
                        type_name: "uLongf".to_string(),
                        is_pointer: true,
                        is_const: false,
                    },
                    ParameterInfo {
                        name: "source".to_string(),
                        type_name: "Bytef".to_string(),
                        is_pointer: true,
                        is_const: true,
                    },
                    ParameterInfo {
                        name: "sourceLen".to_string(),
                        type_name: "uLong".to_string(),
                        is_pointer: false,
                        is_const: false,
                    },
                ],
                file_path: PathBuf::from("compress.c"),
                line_number: 50,
                is_static: false,
                is_exported: true,
                has_body: true,
            },
        },
        BenchmarkCase {
            target_name: "zlib",
            header_name: "zlib.h",
            func: FunctionSignature {
                name: "uncompress".to_string(),
                return_type: "int".to_string(),
                parameters: vec![
                    ParameterInfo {
                        name: "dest".to_string(),
                        type_name: "Bytef".to_string(),
                        is_pointer: true,
                        is_const: false,
                    },
                    ParameterInfo {
                        name: "destLen".to_string(),
                        type_name: "uLongf".to_string(),
                        is_pointer: true,
                        is_const: false,
                    },
                    ParameterInfo {
                        name: "source".to_string(),
                        type_name: "Bytef".to_string(),
                        is_pointer: true,
                        is_const: true,
                    },
                    ParameterInfo {
                        name: "sourceLen".to_string(),
                        type_name: "uLong".to_string(),
                        is_pointer: false,
                        is_const: false,
                    },
                ],
                file_path: PathBuf::from("uncompr.c"),
                line_number: 60,
                is_static: false,
                is_exported: true,
                has_body: true,
            },
        },
        BenchmarkCase {
            target_name: "zlib",
            header_name: "zlib.h",
            func: FunctionSignature {
                name: "deflate".to_string(),
                return_type: "int".to_string(),
                parameters: vec![
                    ParameterInfo {
                        name: "strm".to_string(),
                        type_name: "z_stream".to_string(),
                        is_pointer: true,
                        is_const: false,
                    },
                    ParameterInfo {
                        name: "flush".to_string(),
                        type_name: "int".to_string(),
                        is_pointer: false,
                        is_const: false,
                    },
                ],
                file_path: PathBuf::from("deflate.c"),
                line_number: 70,
                is_static: false,
                is_exported: true,
                has_body: true,
            },
        },
        BenchmarkCase {
            target_name: "zlib",
            header_name: "zlib.h",
            func: FunctionSignature {
                name: "inflate".to_string(),
                return_type: "int".to_string(),
                parameters: vec![
                    ParameterInfo {
                        name: "strm".to_string(),
                        type_name: "z_stream".to_string(),
                        is_pointer: true,
                        is_const: false,
                    },
                    ParameterInfo {
                        name: "flush".to_string(),
                        type_name: "int".to_string(),
                        is_pointer: false,
                        is_const: false,
                    },
                ],
                file_path: PathBuf::from("inflate.c"),
                line_number: 80,
                is_static: false,
                is_exported: true,
                has_body: true,
            },
        },
        BenchmarkCase {
            target_name: "sqlite3",
            header_name: "sqlite3.h",
            func: FunctionSignature {
                name: "sqlite3_open".to_string(),
                return_type: "int".to_string(),
                parameters: vec![
                    ParameterInfo {
                        name: "filename".to_string(),
                        type_name: "char".to_string(),
                        is_pointer: true,
                        is_const: true,
                    },
                    ParameterInfo {
                        name: "ppDb".to_string(),
                        type_name: "sqlite3*".to_string(),
                        is_pointer: true,
                        is_const: false,
                    },
                ],
                file_path: PathBuf::from("sqlite3.c"),
                line_number: 90,
                is_static: false,
                is_exported: true,
                has_body: true,
            },
        },
        BenchmarkCase {
            target_name: "sqlite3",
            header_name: "sqlite3.h",
            func: FunctionSignature {
                name: "sqlite3_close".to_string(),
                return_type: "int".to_string(),
                parameters: vec![ParameterInfo {
                    name: "db".to_string(),
                    type_name: "sqlite3".to_string(),
                    is_pointer: true,
                    is_const: false,
                }],
                file_path: PathBuf::from("sqlite3.c"),
                line_number: 100,
                is_static: false,
                is_exported: true,
                has_body: true,
            },
        },
        BenchmarkCase {
            target_name: "libpng",
            header_name: "png.h",
            func: FunctionSignature {
                name: "png_set_sig_bytes".to_string(),
                return_type: "void".to_string(),
                parameters: vec![
                    ParameterInfo {
                        name: "png_ptr".to_string(),
                        type_name: "png_struct".to_string(),
                        is_pointer: true,
                        is_const: false,
                    },
                    ParameterInfo {
                        name: "num_bytes".to_string(),
                        type_name: "int".to_string(),
                        is_pointer: false,
                        is_const: false,
                    },
                ],
                file_path: PathBuf::from("png.c"),
                line_number: 110,
                is_static: false,
                is_exported: true,
                has_body: true,
            },
        },
    ];

    let total_cases = test_suite.len();
    let mut compiled_first_try = 0;

    let dummy_client = crashwise_agent::LlmClient::new("http://localhost".to_string(), None, "test".to_string());
    let synth = HarnessSynthesizer::new(dummy_client);

    let include_dirs = vec![include_dir];
    let static_libs = vec![lib_path];

    for (idx, case) in test_suite.iter().enumerate() {
        let harness_code = HarnessSynthesizer::synthesize_deterministic_harness(
            &case.func,
            Some(case.target_name),
            Some(case.header_name),
        );

        let harness_src = out_dir.join(format!("test_harness_{}_{}.cpp", case.target_name, idx));
        let harness_bin = out_dir.join(format!("test_bin_{}_{}", case.target_name, idx));

        std::fs::write(&harness_src, &harness_code).unwrap();

        match synth
            .compile_harness(&harness_src, &harness_bin, &include_dirs, &static_libs)
            .await
        {
            Ok(_) => {
                assert!(harness_bin.exists());
                compiled_first_try += 1;
            }
            Err(e) => {
                eprintln!(
                    "Compilation failed for {} ({}): {}",
                    case.target_name, case.func.name, e
                );
            }
        }
    }

    let success_rate = (compiled_first_try as f64) / (total_cases as f64);
    println!(
        "Benchmark First-Attempt Compilation Rate: {}/{} ({:.1}%)",
        compiled_first_try,
        total_cases,
        success_rate * 100.0
    );

    // Mandate: First-Attempt Compilation Success must exceed 80% (> 0.80)
    assert!(
        success_rate >= 0.80,
        "Expected first-attempt compilation success rate >= 80%, got {:.1}% ({}/{})",
        success_rate * 100.0,
        compiled_first_try,
        total_cases
    );
}
